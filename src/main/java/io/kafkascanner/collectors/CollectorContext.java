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
    @Nullable String connectUrl,
    @Nullable String schemaRegistryUrl,
    @Nullable String restProxyUrl,
    @Nullable String docsDir,
    @Nullable String prometheusUrl,
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

    public boolean hasConnectUrl() {
        return connectUrl != null && !connectUrl.isBlank();
    }

    public boolean hasSchemaRegistryUrl() {
        return schemaRegistryUrl != null && !schemaRegistryUrl.isBlank();
    }

    public boolean hasRestProxyUrl() {
        return restProxyUrl != null && !restProxyUrl.isBlank();
    }

    public boolean hasDocsDir() {
        return docsDir != null && !docsDir.isBlank();
    }

    public boolean hasPrometheusUrl() {
        return prometheusUrl != null && !prometheusUrl.isBlank();
    }
}
