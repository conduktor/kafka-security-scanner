package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.common.errors.SecurityDisabledException;

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
            putAclOrRecordDisabled(data, acls, timeoutSeconds);
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
        aclMeta.put("authorizer_enabled",
            !Boolean.FALSE.equals(data.get("acl_authorizer_enabled")));
        if (data.get("acl_collect_error") instanceof String error) {
            aclMeta.put("error", error);
        }
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

        // Detect well-known audit / contract / DLQ system topics so policy controls
        // can prove a Confluent / Apicurio audit pipeline exists by topic presence
        // instead of by docs file. These names are the documented Confluent /
        // Apicurio defaults; allow either prefixed (`_`) or non-prefixed.
        boolean auditLogTopicPresent = false;
        boolean dataContractsTopicPresent = false;
        boolean dlqTopicPresent = false;
        for (var t : topicList) {
            var name = String.valueOf(t.getOrDefault("name", "")).toLowerCase(java.util.Locale.ROOT);
            if (name.contains("confluent-audit-log-events") || name.contains("confluent_audit_log")) {
                auditLogTopicPresent = true;
            }
            if (name.contains("data-contracts") || name.contains("_data_contracts")
                || name.contains("apicurio-registry") || name.contains("kafkasql-journal")) {
                dataContractsTopicPresent = true;
            }
            if (name.endsWith("-dlq") || name.endsWith("_dlq") || name.endsWith(".dlq")
                || name.contains("dead-letter") || name.contains("deadletter")) {
                dlqTopicPresent = true;
            }
        }
        topicMeta.put("audit_log_topic_present", auditLogTopicPresent);
        topicMeta.put("data_contracts_topic_present", dataContractsTopicPresent);
        topicMeta.put("dlq_topic_present", dlqTopicPresent);

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

    private static void putAclOrRecordDisabled(
        Map<String, Object> data,
        java.util.concurrent.Future<?> future,
        int timeoutSeconds
    ) {
        try {
            data.put("acl", future.get(timeoutSeconds, TimeUnit.SECONDS));
        } catch (Exception e) {
            var root = rootCause(e);
            if (root instanceof SecurityDisabledException || isNoAuthorizer(root)) {
                data.put("acl", List.of());
                data.put("acl_authorizer_enabled", false);
                data.put("acl_collect_error", root.getClass().getSimpleName()
                    + ": " + root.getMessage());
                System.err.println("[adminclient] acl authorizer disabled; "
                    + "treating ACL evidence as empty");
                return;
            }
            System.err.println("[adminclient] acl collect failed: " + e.getMessage());
        }
    }

    private static Throwable rootCause(Throwable throwable) {
        var current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    private static boolean isNoAuthorizer(Throwable throwable) {
        var message = throwable.getMessage();
        return message != null && message.contains("No Authorizer is configured");
    }
}
