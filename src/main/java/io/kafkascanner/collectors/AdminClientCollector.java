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
