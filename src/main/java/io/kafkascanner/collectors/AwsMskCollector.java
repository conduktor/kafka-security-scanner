package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.Map;

/**
 * Inspects an AWS MSK cluster via the AWS SDK. Activates when
 * {@code --aws-region} is set or when the detected flavor is
 * {@link io.kafkascanner.flavor.FlavorDetector#AWS_MSK}.
 *
 * <p>Implementation pending: the AWS SDK v2 modular dependency is
 * intentionally not yet wired so the JAR stays small. This stub keeps the
 * `aws` namespace populated with detection metadata so policy controls
 * can already gate on it.
 */
public final class AwsMskCollector implements Collector {

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
        out.put("sdk_available", false);
        out.put("encryption_at_rest", false);
        out.put("encryption_in_transit_client", false);
        out.put("encryption_in_transit_in_cluster", false);
        out.put("public_access", false);
        out.put("under_replicated_partitions_max", -1L);
        out.put("offline_partitions_count_max", -1L);
        out.put("any_sg_open_to_world", false);
        return Map.of("aws", out);
    }
}
