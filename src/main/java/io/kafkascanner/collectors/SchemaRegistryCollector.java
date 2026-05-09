package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Probes Confluent Schema Registry. Pass {@code --schema-registry-url
 * http://host:8081}. Populates {@code schemaregistry}.
 */
public final class SchemaRegistryCollector implements Collector {

    @Override
    public String name() {
        return "schemaregistry";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasSchemaRegistryUrl();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var url = context.schemaRegistryUrl();
        if (url == null) {
            return Map.of();
        }
        var base = url.replaceAll("/+$", "");
        var rootResp = HttpProbe.get(base + "/subjects", context.timeout());
        var out = new HashMap<String, Object>(rootResp);

        var subjects = rootResp.get("body");
        if (subjects instanceof List<?> list) {
            out.put("subject_count", (long) list.size());
        } else {
            out.put("subject_count", 0L);
        }

        var configResp = HttpProbe.get(base + "/config", context.timeout());
        var configBody = configResp.get("body");
        if (configBody instanceof Map<?, ?> m) {
            var compat = String.valueOf(m.get("compatibilityLevel"));
            out.put("compatibility_level", compat);
            // Compatibility modes that prevent breaking changes for consumers.
            out.put("compatibility_protects_consumers",
                compat.toUpperCase(Locale.ROOT).startsWith("BACKWARD")
                    || compat.toUpperCase(Locale.ROOT).equals("FULL")
                    || compat.toUpperCase(Locale.ROOT).startsWith("FULL_"));
        } else {
            out.put("compatibility_level", "UNKNOWN");
            out.put("compatibility_protects_consumers", false);
        }

        return Map.of("schemaregistry", out);
    }
}
