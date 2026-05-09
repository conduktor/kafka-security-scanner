package io.kafkascanner.collectors;

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
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.config.ConfigResource;

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
            if (!listenerMap.isEmpty()) {
                for (var mapping : listenerMap.split(",")) {
                    var parts = mapping.split(":");
                    if (parts.length == 2) {
                        listeners.add(Map.of("protocol", parts[1].trim()));
                    }
                }
            } else {
                listeners.add(Map.of("protocol", "PLAINTEXT"));
            }

            var brokerEntry = new HashMap<String, Object>();
            brokerEntry.put("broker_id", (long) node.id());
            brokerEntry.put("host", node.host());
            brokerEntry.put("is_controller", node.id() == controller.id());
            brokerEntry.put("config", configMap);
            brokerEntry.put("listeners", listeners);
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
        var topics = admin.listTopics().names().get(timeoutSeconds, TimeUnit.SECONDS);
        var descriptions = admin.describeTopics(topics).allTopicNames().get(timeoutSeconds, TimeUnit.SECONDS);

        return descriptions.entrySet().stream().map(e -> {
            var desc = e.getValue();
            var partitions = desc.partitions();
            var rf = partitions.isEmpty() ? 1 : partitions.get(0).replicas().size();
            var urp = partitions.stream().filter(p -> p.isr().size() < p.replicas().size()).count();
            var offline = partitions.stream().filter(p -> p.leader().id() == -1).count();

            var result = new HashMap<String, Object>();
            result.put("name", e.getKey());
            result.put("partitions", (long) partitions.size());
            result.put("replication_factor", (long) rf);
            result.put("under_replicated_partitions", urp);
            result.put("offline_partitions", offline);
            return result;
        }).collect(Collectors.toList());
    }

    static List<Map<String, Object>> collectAcls(AdminClient admin, int timeoutSeconds) throws Exception {
        var acls = admin.describeAcls(AclBindingFilter.ANY).values().get(timeoutSeconds, TimeUnit.SECONDS);
        return acls.stream().map(acl -> {
            var m = new HashMap<String, Object>();
            m.put("principal", acl.entry().principal());
            m.put("host", acl.entry().host());
            m.put("operation", acl.entry().operation().name());
            m.put("resource_type", acl.pattern().resourceType().name());
            m.put("resource_name", acl.pattern().name());
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
        // Detect KRaft vs ZooKeeper. Modern Kafka always advertises a controller node,
        // and AdminClient's metadata identifies KRaft when listNodes returns the controller
        // alongside brokers. Without the legacy /controller znode lookup we conservatively
        // default to "kraft" — Kafka 4.x dropped ZooKeeper anyway. ZK-bound checks become
        // vacuously true when mode != 'zookeeper'.
        var mode = "kraft";
        return Map.of(
            "controller_id", (long) controller.id(),
            "voters", nodes.stream().map(n -> (long) n.id()).toList(),
            "healthy", !nodes.isEmpty(),
            "quorum_size", (long) nodes.size(),
            "mode", mode
        );
    }
}
