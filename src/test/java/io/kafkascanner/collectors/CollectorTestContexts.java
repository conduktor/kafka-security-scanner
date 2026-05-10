package io.kafkascanner.collectors;

import java.time.Duration;
import java.util.Map;

@SuppressWarnings("NullAway")
final class CollectorTestContexts {
    private CollectorTestContexts() { }

    static CollectorContext ecosystem(String connectUrl, String schemaRegistryUrl,
                                      boolean activeProbesAllowed) {
        return new CollectorContext(
            "broker:9092",
            Duration.ofSeconds(2),
            null,
            null,
            null,
            blankToNull(connectUrl),
            blankToNull(schemaRegistryUrl),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            Map.of(),
            "vanilla",
            activeProbesAllowed);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
