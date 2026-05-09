package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Collector that talks to the Kafka AdminClient: brokers, topics, ACLs, KRaft state.
 * Populates the keys {@code broker}, {@code topic}, {@code acl}, {@code kraft} on the
 * scan data map (which CEL exposes as {@code brokers}, {@code topics}, {@code acls},
 * {@code cluster}).
 */
public final class AdminClientCollector implements Collector {

    @Override
    public String name() {
        return "adminclient";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasAdminClient();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var admin = context.adminClient();
        if (admin == null) {
            return Map.of();
        }
        var timeoutSeconds = (int) context.timeout().toSeconds();
        var data = new HashMap<String, Object>();

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var brokers = executor.submit(() ->
                KafkaCollectors.collectBrokers(admin, timeoutSeconds));
            var topics = executor.submit(() ->
                KafkaCollectors.collectTopics(admin, timeoutSeconds));
            var acls = executor.submit(() ->
                KafkaCollectors.collectAcls(admin, timeoutSeconds));
            var cluster = executor.submit(() ->
                KafkaCollectors.collectCluster(admin, timeoutSeconds));
            var quotas = executor.submit(() ->
                KafkaCollectors.collectQuotas(admin, timeoutSeconds));

            putOrLog(data, "broker", brokers, timeoutSeconds, "broker");
            putOrLog(data, "topic", topics, timeoutSeconds, "topic");
            putOrLog(data, "acl", acls, timeoutSeconds, "acl");
            putOrLog(data, "kraft", cluster, timeoutSeconds, "kraft");
            putOrLog(data, "quota", quotas, timeoutSeconds, "quota");
        }
        // Cross-cut metadata so CEL can disambiguate "no ACLs" from "ACL collector failed".
        @SuppressWarnings("unchecked")
        var aclList = data.get("acl") instanceof java.util.List<?> l
            ? (java.util.List<Map<String, Object>>) l
            : java.util.List.<Map<String, Object>>of();
        var aclMeta = new java.util.HashMap<String, Object>();
        aclMeta.put("collected", data.containsKey("acl"));
        aclMeta.put("count", (long) aclList.size());
        aclMeta.put("distinct_principal_count", aclList.stream()
            .map(a -> a.getOrDefault("principal", ""))
            .distinct()
            .count());
        data.put("acl_metadata", aclMeta);

        @SuppressWarnings("unchecked")
        var topicList = data.get("topic") instanceof java.util.List<?> l
            ? (java.util.List<Map<String, Object>>) l
            : java.util.List.<Map<String, Object>>of();
        var topicMeta = new java.util.HashMap<String, Object>();
        topicMeta.put("collected", data.containsKey("topic"));
        topicMeta.put("count", (long) topicList.size());
        data.put("topic_metadata", topicMeta);

        @SuppressWarnings("unchecked")
        var quotaList = data.get("quota") instanceof java.util.List<?> l
            ? (java.util.List<Map<String, Object>>) l
            : java.util.List.<Map<String, Object>>of();
        var quotaMeta = new java.util.HashMap<String, Object>();
        quotaMeta.put("collected", data.containsKey("quota"));
        quotaMeta.put("count", (long) quotaList.size());
        data.put("quota_metadata", quotaMeta);

        return data;
    }

    private static void putOrLog(
        Map<String, Object> data, String key,
        java.util.concurrent.Future<?> future, int timeoutSeconds, String name
    ) {
        try {
            data.put(key, future.get(timeoutSeconds, TimeUnit.SECONDS));
        } catch (Exception e) {
            System.err.println("[adminclient] " + name + " collect failed: " + e.getMessage());
        }
    }
}
