package io.kafkascanner.collectors;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchClient;
import software.amazon.awssdk.services.cloudwatch.model.Dimension;
import software.amazon.awssdk.services.cloudwatch.model.GetMetricStatisticsRequest;
import software.amazon.awssdk.services.cloudwatch.model.Statistic;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeSecurityGroupsRequest;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.IpRange;
import software.amazon.awssdk.services.ec2.model.Ipv6Range;
import software.amazon.awssdk.services.kafka.KafkaClient;
import software.amazon.awssdk.services.kafka.model.ClusterInfo;
import software.amazon.awssdk.services.kafka.model.ListClustersRequest;
import software.amazon.awssdk.services.kafka.model.PublicAccess;

/**
 * Inspects an AWS MSK cluster via the AWS SDK. Activates when
 * {@code --aws-region} is set or when the detected flavor is
 * {@link io.kafkascanner.flavor.FlavorDetector#AWS_MSK}.
 *
 * <p>What we collect:
 * <ul>
 *   <li>{@code DescribeCluster} (or list+filter by name): encryption-at-rest,
 *       in-transit encryption (client + in-cluster), public-access mode, broker
 *       SG ids.</li>
 *   <li>{@code DescribeSecurityGroups} for each broker SG: any 0.0.0.0/0 or
 *       ::/0 ingress rule on broker ports 9092/9094/9098 is a fail.</li>
 *   <li>{@code GetMetricStatistics} CloudWatch:
 *       UnderReplicatedPartitions / OfflinePartitionsCount over the last hour
 *       (max). MSK does not expose JMX so this is the only path to those
 *       reliability metrics.</li>
 * </ul>
 *
 * <p>Uses the default credential chain (env vars / profile / IRSA / EC2 IMDSv2).
 * Failures fall through to {@code aws.sdk_available=false} so policy controls
 * short-circuit instead of erroring.
 */
public final class AwsMskCollector implements Collector {

    private static final int[] BROKER_PORTS = {9092, 9094, 9098};

    @Override
    public String name() {
        return "awsmsk";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasAwsConfig() || "aws-msk".equals(context.kafkaFlavor());
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();
        out.put("flavor_detected", "aws-msk".equals(context.kafkaFlavor()));
        out.put("region", context.awsRegion() == null ? "" : context.awsRegion());
        out.put("cluster_arn", context.awsMskClusterArn() == null ? "" : context.awsMskClusterArn());
        // Default-state fields so policy CEL can reference them on the negative path.
        out.put("sdk_available", false);
        out.put("encryption_at_rest", false);
        out.put("encryption_in_transit_client", "");
        out.put("encryption_in_transit_in_cluster", false);
        out.put("public_access", false);
        out.put("under_replicated_partitions_max", -1L);
        out.put("offline_partitions_count_max", -1L);
        out.put("any_sg_open_to_world", false);
        out.put("security_groups_inspected", List.of());
        out.put("error", "");

        var region = pickRegion(context);
        if (region == null) {
            out.put("error", "no AWS region (set --aws-region or AWS_REGION)");
            return Map.of("aws", out);
        }
        out.put("region", region.id());

        ClusterInfo cluster;
        try (var kafka = KafkaClient.builder().region(region).build()) {
            cluster = findCluster(kafka, context.awsMskClusterArn(), context.bootstrap());
            if (cluster == null) {
                out.put("error", "no MSK cluster matched (region=" + region.id() + ")");
                out.put("sdk_available", true);
                return Map.of("aws", out);
            }
        } catch (Exception e) {
            out.put("error", "kafka:" + e.getClass().getSimpleName() + ":" + e.getMessage());
            return Map.of("aws", out);
        }

        out.put("sdk_available", true);
        out.put("cluster_arn", cluster.clusterArn());
        out.put("cluster_name", cluster.clusterName());
        out.put("kafka_version",
            cluster.currentBrokerSoftwareInfo() == null
                ? "" : String.valueOf(cluster.currentBrokerSoftwareInfo().kafkaVersion()));

        var brokerInfo = cluster.brokerNodeGroupInfo();
        var sgIds = new ArrayList<String>();
        if (brokerInfo != null) {
            if (brokerInfo.securityGroups() != null) {
                sgIds.addAll(brokerInfo.securityGroups());
            }
            if (brokerInfo.connectivityInfo() != null
                && brokerInfo.connectivityInfo().publicAccess() != null) {
                var pa = brokerInfo.connectivityInfo().publicAccess();
                out.put("public_access", isPublicAccessEnabled(pa));
            }
        }

        var enc = cluster.encryptionInfo();
        if (enc != null) {
            if (enc.encryptionAtRest() != null
                && enc.encryptionAtRest().dataVolumeKMSKeyId() != null
                && !enc.encryptionAtRest().dataVolumeKMSKeyId().isBlank()) {
                out.put("encryption_at_rest", true);
                out.put("encryption_at_rest_kms_key", enc.encryptionAtRest().dataVolumeKMSKeyId());
            }
            if (enc.encryptionInTransit() != null) {
                out.put("encryption_in_transit_client",
                    String.valueOf(enc.encryptionInTransit().clientBrokerAsString()));
                out.put("encryption_in_transit_in_cluster",
                    Boolean.TRUE.equals(enc.encryptionInTransit().inCluster()));
            }
        }

        // SG ingress audit
        if (!sgIds.isEmpty()) {
            try (var ec2 = Ec2Client.builder().region(region).build()) {
                var resp = ec2.describeSecurityGroups(DescribeSecurityGroupsRequest.builder()
                    .groupIds(sgIds)
                    .build());
                boolean anyOpen = false;
                var inspected = new ArrayList<Map<String, Object>>();
                for (var sg : resp.securityGroups()) {
                    var openPorts = openBrokerPorts(sg.ipPermissions());
                    inspected.add(Map.of(
                        "id", (Object) sg.groupId(),
                        "name", (Object) sg.groupName(),
                        "open_broker_ports", openPorts
                    ));
                    if (!openPorts.isEmpty()) {
                        anyOpen = true;
                    }
                }
                out.put("any_sg_open_to_world", anyOpen);
                out.put("security_groups_inspected", inspected);
            } catch (Exception e) {
                out.put("error", "ec2:" + e.getMessage());
            }
        }

        // CloudWatch metrics: max URP / offline over the last hour
        try (var cw = CloudWatchClient.builder().region(region).build()) {
            var clusterName = cluster.clusterName();
            var arn = cluster.clusterArn();
            var dims = List.of(
                Dimension.builder().name("Cluster Name").value(clusterName).build()
            );
            // MSK CloudWatch uses "Cluster Name" (default monitoring) or richer
            // dimensions for ENHANCED. Try the basic dimension first.
            out.put("under_replicated_partitions_max",
                queryMax(cw, "AWS/Kafka", "UnderReplicatedPartitions", dims));
            out.put("offline_partitions_count_max",
                queryMax(cw, "AWS/Kafka", "OfflinePartitionsCount", dims));
            out.put("cluster_arn", arn);
        } catch (Exception e) {
            out.put("error", "cloudwatch:" + e.getMessage());
        }

        return Map.of("aws", out);
    }

    private static @Nullable Region pickRegion(CollectorContext context) {
        var configuredRegion = context.awsRegion();
        if (configuredRegion != null && !configuredRegion.isBlank()) {
            return Region.of(configuredRegion);
        }
        // Try parse from cluster ARN
        var clusterArn = context.awsMskClusterArn();
        if (clusterArn != null && !clusterArn.isBlank()) {
            var parts = clusterArn.split(":");
            if (parts.length >= 4 && !parts[3].isBlank()) {
                return Region.of(parts[3]);
            }
        }
        // Fall back to AWS_REGION env var (the SDK will also check, but we want the value)
        var envRegion = System.getenv("AWS_REGION");
        if (envRegion == null) {
            envRegion = System.getenv("AWS_DEFAULT_REGION");
        }
        if (envRegion != null && !envRegion.isBlank()) {
            return Region.of(envRegion);
        }
        return null;
    }

    private static @Nullable ClusterInfo findCluster(KafkaClient kafka,
                                                     @Nullable String arn,
                                                     String bootstrap) {
        // List up to 100 clusters, filter:
        //   1) explicit ARN match
        //   2) bootstrap host substring match against cluster name
        var resp = kafka.listClusters(ListClustersRequest.builder().maxResults(100).build());
        if (resp.clusterInfoList().isEmpty()) {
            return null;
        }
        if (arn != null && !arn.isBlank()) {
            for (var c : resp.clusterInfoList()) {
                if (arn.equals(c.clusterArn())) {
                    return c;
                }
            }
            return null;
        }
        var hostLower = bootstrap.split(",", 2)[0].toLowerCase(Locale.ROOT);
        for (var c : resp.clusterInfoList()) {
            var name = c.clusterName() == null ? "" : c.clusterName().toLowerCase(Locale.ROOT);
            if (!name.isEmpty() && hostLower.contains(name)) {
                return c;
            }
        }
        // Single-cluster region: just return it.
        if (resp.clusterInfoList().size() == 1) {
            return resp.clusterInfoList().get(0);
        }
        return null;
    }

    private static boolean isPublicAccessEnabled(PublicAccess pa) {
        var type = pa.type();
        return type != null
            && !"DISABLED".equalsIgnoreCase(type)
            && !type.toUpperCase(Locale.ROOT).contains("DISABLED");
    }

    private static List<Long> openBrokerPorts(List<IpPermission> permissions) {
        var open = new ArrayList<Long>();
        if (permissions == null) {
            return open;
        }
        for (var perm : permissions) {
            if (perm == null) {
                continue;
            }
            int from = perm.fromPort() == null ? 0 : perm.fromPort();
            int to = perm.toPort() == null ? 65535 : perm.toPort();
            boolean openWorld = false;
            if (perm.ipRanges() != null) {
                for (IpRange r : perm.ipRanges()) {
                    if ("0.0.0.0/0".equals(r.cidrIp())) {
                        openWorld = true;
                        break;
                    }
                }
            }
            if (!openWorld && perm.ipv6Ranges() != null) {
                for (Ipv6Range r : perm.ipv6Ranges()) {
                    if ("::/0".equals(r.cidrIpv6())) {
                        openWorld = true;
                        break;
                    }
                }
            }
            if (!openWorld) {
                continue;
            }
            for (int p : BROKER_PORTS) {
                if (p >= from && p <= to) {
                    open.add((long) p);
                }
            }
        }
        return open;
    }

    private static long queryMax(CloudWatchClient cw, String namespace, String metric,
                                 List<Dimension> dims) {
        try {
            var resp = cw.getMetricStatistics(GetMetricStatisticsRequest.builder()
                .namespace(namespace)
                .metricName(metric)
                .dimensions(dims)
                .startTime(Instant.now().minus(1, ChronoUnit.HOURS))
                .endTime(Instant.now())
                .period(300)
                .statistics(Statistic.MAXIMUM)
                .build());
            return resp.datapoints().stream()
                .filter(d -> d.maximum() != null)
                .mapToLong(d -> d.maximum().longValue())
                .max()
                .orElse(-1L);
        } catch (RuntimeException e) {
            System.err.println("[awsmsk] CloudWatch metric " + metric + " failed: "
                + e.getMessage());
            return -1L;
        }
    }

    /** Test hook. */
    static int[] brokerPorts() {
        return Arrays.copyOf(BROKER_PORTS, BROKER_PORTS.length);
    }
}
