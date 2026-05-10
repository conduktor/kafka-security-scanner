package io.kafkascanner.collectors;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.ListTopicsOptions;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.config.ConfigResource;
import org.apache.kafka.common.quota.ClientQuotaFilter;

/** Collects cluster metadata via Kafka AdminClient using virtual threads. */

public final class KafkaCollectors {
    private KafkaCollectors() {}

    /** Collect all data using virtual threads for parallelism. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> collectAll(AdminClient admin, int maxWorkers, int timeoutSeconds)
            throws Exception {
        var data = new ConcurrentHashMap<String, Object>();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var futures = List.of(
                executor.submit(() -> {
                    data.put("broker", collectBrokers(admin, timeoutSeconds));
                    return null;
                }),
                executor.submit(() -> {
                    data.put("topic", collectTopics(admin, timeoutSeconds));
                    return null;
                }),
                executor.submit(() -> {
                    data.put("acl", collectAcls(admin, timeoutSeconds));
                    return null;
                }),
                executor.submit(() -> {
                    data.put("kraft", collectCluster(admin, timeoutSeconds));
                    return null;
                })
            );
            for (var f : futures) {
                try {
                    f.get(timeoutSeconds, TimeUnit.SECONDS);
                } catch (Exception e) {
                    System.err.println("Collector failed: " + e.getMessage());
                }
            }
        }
        return data;
    }

    public static Map<String, Object> collectAll(AdminClient admin, int maxWorkers) throws Exception {
        return collectAll(admin, maxWorkers, 30);
    }

    @SuppressWarnings("StringSplitter")
    static List<Map<String, Object>> collectBrokers(AdminClient admin, int timeoutSeconds) throws Exception {
        var cluster = admin.describeCluster();
        var nodes = cluster.nodes().get(timeoutSeconds, TimeUnit.SECONDS);
        var controller = cluster.controller().get(timeoutSeconds, TimeUnit.SECONDS);

        var result = new ArrayList<Map<String, Object>>();
        for (var node : nodes) {
            var configResource = new ConfigResource(ConfigResource.Type.BROKER, String.valueOf(node.id()));
            var allConfigs = admin.describeConfigs(List.of(configResource))
                .all().get(timeoutSeconds, TimeUnit.SECONDS);
            var config = allConfigs.get(configResource);

            var configMap = new HashMap<String, String>();
            if (config != null) {
                for (var entry : config.entries()) {
                    configMap.put(entry.name(), entry.value());
                }
            }

            var sasl = new HashMap<String, Object>();
            if (configMap.containsKey("sasl.enabled.mechanisms")) {
                sasl.put("enabled", true);
                sasl.put("mechanisms", List.of(configMap.get("sasl.enabled.mechanisms").split(",")));
            }

            var tls = new HashMap<String, Object>();
            tls.put("enabled",
                configMap.containsKey("ssl.keystore.location")
                || configMap.containsKey("ssl.enabled.protocols"));

            var listeners = new ArrayList<Map<String, Object>>();
            var listenerMap = configMap.getOrDefault("listener.security.protocol.map", "");
            var distinctProtocols = new java.util.LinkedHashSet<String>();
            if (!listenerMap.isEmpty()) {
                for (var mapping : listenerMap.split(",")) {
                    var parts = mapping.split(":");
                    if (parts.length == 2) {
                        var name = parts[0].trim();
                        var proto = parts[1].trim().toUpperCase(java.util.Locale.ROOT);
                        listeners.add(Map.of("name", (Object) name, "protocol", (Object) proto));
                        distinctProtocols.add(proto);
                    }
                }
            } else {
                listeners.add(Map.of("name", (Object) "PLAINTEXT", "protocol", (Object) "PLAINTEXT"));
                distinctProtocols.add("PLAINTEXT");
            }

            // Pre-parse numeric configs so CEL conditions can compare with `<`/`>` —
            // cel-java's int() does not accept strings.
            var configInt = new HashMap<String, Long>();
            for (var entry : configMap.entrySet()) {
                var v = entry.getValue();
                if (v == null || v.isEmpty()) {
                    continue;
                }
                try {
                    configInt.put(entry.getKey(), Long.parseLong(v.trim()));
                } catch (NumberFormatException ignored) {
                    // non-numeric config: skip
                }
            }

            // DNS audit on advertised.listeners — controls (NET-002) need to know
            // whether any advertised host resolves to a public IP.
            var advertisedAudit = auditAdvertisedHosts(
                configMap.getOrDefault("advertised.listeners", ""));

            var brokerEntry = new HashMap<String, Object>();
            brokerEntry.put("broker_id", (long) node.id());
            brokerEntry.put("host", node.host());
            brokerEntry.put("is_controller", node.id() == controller.id());
            brokerEntry.put("config", configMap);
            brokerEntry.put("config_int", configInt);
            brokerEntry.put("listeners", listeners);
            brokerEntry.put("listener_protocol_classes", new ArrayList<>(distinctProtocols));
            brokerEntry.put("listener_protocols_distinct_count", (long) distinctProtocols.size());
            brokerEntry.put("advertised_hosts", advertisedAudit.hosts);
            brokerEntry.put("advertised_hosts_public", advertisedAudit.anyPublic);
            brokerEntry.put("advertised_hosts_unresolved", advertisedAudit.unresolved);
            brokerEntry.put("sasl", sasl);
            brokerEntry.put("tls", tls);
            brokerEntry.put("metrics", new HashMap<String, Double>());
            brokerEntry.put("min_insync_replicas", parseLongConfig(configMap, "min.insync.replicas", 1L));
            brokerEntry.put("num_partitions", parseLongConfig(configMap, "num.partitions", 1L));
            brokerEntry.put("default_replication_factor",
                parseLongConfig(configMap, "default.replication.factor", 1L));
            result.add(brokerEntry);
        }
        return result;
    }

    static List<Map<String, Object>> collectTopics(AdminClient admin, int timeoutSeconds) throws Exception {
        // listInternal(true) so KAFKA-ACL-012 (every internal topic protected) and
        // similar coverage checks see _consumer_offsets, __transaction_state, etc.
        var topics = admin.listTopics(new ListTopicsOptions().listInternal(true))
            .names().get(timeoutSeconds, TimeUnit.SECONDS);
        var descriptions = admin.describeTopics(topics).allTopicNames().get(timeoutSeconds, TimeUnit.SECONDS);

        // Fetch per-topic dynamic configs (retention.ms, cleanup.policy, classification labels).
        var configResources = topics.stream()
            .map(t -> new ConfigResource(ConfigResource.Type.TOPIC, t))
            .toList();
        Map<ConfigResource, org.apache.kafka.clients.admin.Config> topicConfigs;
        try {
            topicConfigs = admin.describeConfigs(configResources)
                .all().get(timeoutSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            topicConfigs = Map.of();
        }

        var result = new ArrayList<Map<String, Object>>();
        for (var e : descriptions.entrySet()) {
            var desc = e.getValue();
            var partitions = desc.partitions();
            var rf = partitions.isEmpty() ? 1 : partitions.get(0).replicas().size();
            var urp = partitions.stream().filter(p -> p.isr().size() < p.replicas().size()).count();
            var offline = partitions.stream().filter(p -> p.leader().id() == -1).count();

            var configMap = new HashMap<String, String>();
            var resource = new ConfigResource(ConfigResource.Type.TOPIC, e.getKey());
            var cfg = topicConfigs.get(resource);
            if (cfg != null) {
                for (var ce : cfg.entries()) {
                    if (ce.value() != null) {
                        configMap.put(ce.name(), ce.value());
                    }
                }
            }

            var entry = new HashMap<String, Object>();
            entry.put("name", e.getKey());
            entry.put("partitions", (long) partitions.size());
            entry.put("replication_factor", (long) rf);
            entry.put("under_replicated_partitions", urp);
            entry.put("offline_partitions", offline);
            entry.put("config", configMap);
            entry.put("min_insync_replicas",
                parseLongConfig(configMap, "min.insync.replicas", -1L));
            entry.put("retention_ms",
                parseLongConfig(configMap, "retention.ms", -2L));
            entry.put("cleanup_policy",
                configMap.getOrDefault("cleanup.policy", "delete"));
            // Convention: operators tag classification via topic config keys
            // `data.classification` and `data.owner`. We surface them so DATA-* checks
            // can verify the tag is set, not just believe a separate doc exists.
            entry.put("classification",
                configMap.getOrDefault("data.classification", ""));
            entry.put("owner",
                configMap.getOrDefault("data.owner", ""));
            entry.put("has_classification",
                configMap.containsKey("data.classification")
                    && !configMap.get("data.classification").isEmpty());
            entry.put("internal", e.getKey().startsWith("_") || e.getKey().startsWith("__"));
            result.add(entry);
        }
        return result;
    }

    static List<Map<String, Object>> collectQuotas(AdminClient admin, int timeoutSeconds) throws Exception {
        var result = admin.describeClientQuotas(ClientQuotaFilter.all())
            .entities().get(timeoutSeconds, TimeUnit.SECONDS);
        var out = new ArrayList<Map<String, Object>>();
        for (var entry : result.entrySet()) {
            var entity = entry.getKey();
            var values = entry.getValue();
            var m = new HashMap<String, Object>();
            m.put("entity", entity.entries());
            // Common quota keys: producer_byte_rate, consumer_byte_rate, request_percentage,
            // controller_mutation_rate, connection_creation_rate.
            for (var kv : values.entrySet()) {
                m.put(kv.getKey(), kv.getValue());
            }
            // Has-flags so CEL can write `quotas.exists(q, q.has_producer_byte_rate)`.
            m.put("has_producer_byte_rate", values.containsKey("producer_byte_rate"));
            m.put("has_consumer_byte_rate", values.containsKey("consumer_byte_rate"));
            m.put("has_request_percentage", values.containsKey("request_percentage"));
            m.put("has_controller_mutation_rate",
                values.containsKey("controller_mutation_rate"));
            m.put("has_connection_creation_rate",
                values.containsKey("connection_creation_rate"));
            // Entity classification: per-user, per-client-id, per-ip.
            var entries = entity.entries();
            m.put("scoped_to_user", entries.containsKey("user"));
            m.put("scoped_to_client_id", entries.containsKey("client-id"));
            m.put("scoped_to_ip", entries.containsKey("ip"));
            out.add(m);
        }
        return out;
    }

    static List<Map<String, Object>> collectAcls(AdminClient admin, int timeoutSeconds) throws Exception {
        var acls = admin.describeAcls(AclBindingFilter.ANY).values().get(timeoutSeconds, TimeUnit.SECONDS);
        return acls.stream().map(acl -> {
            var m = new HashMap<String, Object>();
            m.put("principal", acl.entry().principal());
            m.put("host", acl.entry().host());
            m.put("operation", acl.entry().operation().name());
            m.put("permission_type", acl.entry().permissionType().name());
            m.put("resource_type", acl.pattern().resourceType().name());
            m.put("resource_name", acl.pattern().name());
            m.put("pattern_type", acl.pattern().patternType().name());
            return Collections.unmodifiableMap(m);
        }).collect(Collectors.toList());
    }

    private static long parseLongConfig(Map<String, String> config, String key, long defaultValue) {
        var raw = config.get(key);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            return Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    static Map<String, Object> collectCluster(AdminClient admin, int timeoutSeconds) throws Exception {
        var cluster = admin.describeCluster();
        var nodes = cluster.nodes().get(timeoutSeconds, TimeUnit.SECONDS);
        var controller = cluster.controller().get(timeoutSeconds, TimeUnit.SECONDS);

        // Detect KRaft vs ZooKeeper from broker config rather than hardcoding.
        // KRaft brokers expose `process.roles` (broker / controller / broker,controller).
        // ZooKeeper-mode brokers do not set it, but expose `zookeeper.connect`.
        var mode = "unknown";
        long voterCount = -1L;
        if (!nodes.isEmpty()) {
            var firstNode = nodes.iterator().next();
            var configResource = new ConfigResource(
                ConfigResource.Type.BROKER, String.valueOf(firstNode.id()));
            try {
                var configs = admin.describeConfigs(List.of(configResource))
                    .all().get(timeoutSeconds, TimeUnit.SECONDS).get(configResource);
                if (configs != null) {
                    var processRoles = configs.get("process.roles");
                    var zkConnect = configs.get("zookeeper.connect");
                    if (processRoles != null && processRoles.value() != null
                        && !processRoles.value().isEmpty()) {
                        mode = "kraft";
                    } else if (zkConnect != null && zkConnect.value() != null
                        && !zkConnect.value().isEmpty()) {
                        mode = "zookeeper";
                    }
                }
            } catch (Exception ignored) {
                // mode stays "unknown"; ZK-bound conditions explicitly handle this.
            }
        }

        if ("kraft".equals(mode)) {
            try {
                var quorum = admin.describeMetadataQuorum()
                    .quorumInfo().get(timeoutSeconds, TimeUnit.SECONDS);
                voterCount = quorum.voters().size();
            } catch (Exception ignored) {
                // describeMetadataQuorum needs Kafka 3.4+. Fallback below.
            }
        }
        if (voterCount < 0) {
            voterCount = nodes.size();
        }

        return Map.of(
            "controller_id", (long) controller.id(),
            "voters", nodes.stream().map(n -> (long) n.id()).toList(),
            "healthy", !nodes.isEmpty(),
            "quorum_size", (long) nodes.size(),
            "voter_count", voterCount,
            "mode", mode
        );
    }

    private record AdvertisedAudit(List<String> hosts, boolean anyPublic, List<String> unresolved) { }

    /**
     * Parse {@code advertised.listeners} (e.g. {@code PLAINTEXT://host:9092,SASL_SSL://host2:9094})
     * and return DNS-resolution metadata. Localhost / 0.0.0.0 / link-local /
     * RFC1918 addresses are private; everything else (including unresolvable
     * hostnames) is flagged so the operator inspects manually.
     */
    private static AdvertisedAudit auditAdvertisedHosts(String advertised) {
        var hosts = new ArrayList<String>();
        var unresolved = new ArrayList<String>();
        boolean anyPublic = false;
        if (advertised == null || advertised.isBlank()) {
            return new AdvertisedAudit(hosts, false, unresolved);
        }
        for (var entry : advertised.split(",")) {
            var t = entry.trim();
            if (t.isEmpty()) {
                continue;
            }
            // strip the listener-name prefix (PLAINTEXT://host:9092 -> host:9092)
            int sep = t.indexOf("://");
            if (sep > 0) {
                t = t.substring(sep + 3);
            }
            int colon = t.lastIndexOf(':');
            var host = colon > 0 ? t.substring(0, colon) : t;
            host = host.replaceAll("[\\[\\]]", "");
            if (host.isBlank() || "0.0.0.0".equals(host) || "::".equals(host)) {
                continue;
            }
            hosts.add(host);
            try {
                var addrs = InetAddress.getAllByName(host);
                boolean publicAddress = false;
                for (var addr : addrs) {
                    if (isPrivate(addr)) {
                        continue;
                    }
                    publicAddress = true;
                    break;
                }
                if (publicAddress) {
                    anyPublic = true;
                }
            } catch (UnknownHostException e) {
                unresolved.add(host);
                anyPublic = true;
            }
        }
        return new AdvertisedAudit(hosts, anyPublic, unresolved);
    }

    /** True for loopback / link-local / site-local / RFC4193 ULA. */
    private static boolean isPrivate(InetAddress addr) {
        return addr.isLoopbackAddress()
            || addr.isLinkLocalAddress()
            || addr.isSiteLocalAddress()
            || addr.isAnyLocalAddress()
            || (addr.getAddress().length == 16 && (addr.getAddress()[0] & 0xfe) == 0xfc);
    }
}
