package io.kafkascanner.collectors;

import java.time.Duration;
import java.util.Map;
import org.apache.kafka.clients.admin.AdminClient;
import org.checkerframework.checker.nullness.qual.Nullable;

/** Shared configuration passed to every collector. */
public record CollectorContext(
    String bootstrap,
    Duration timeout,
    @Nullable AdminClient adminClient,
    @Nullable String kafkaConfigDir,
    @Nullable String jmxHostPort,
    Map<String, String> saslProps,
    String kafkaFlavor
) {
    public boolean hasAdminClient() {
        return adminClient != null;
    }

    public boolean hasKafkaConfigDir() {
        return kafkaConfigDir != null && !kafkaConfigDir.isBlank();
    }

    public boolean hasJmx() {
        return jmxHostPort != null && !jmxHostPort.isBlank();
    }
}
