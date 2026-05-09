package io.kafkascanner.collectors;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Static analysis of secret-bearing config values across every collector
 * snapshot. Proves that a KMS / config-provider is actually referenced
 * for sensitive material instead of plaintext-pasted into properties.
 *
 * <p>Scans:
 * <ul>
 *   <li>{@code broker.config} (AdminClient describeConfigs)</li>
 *   <li>{@code connect.connector_configs[*].config} (per-connector REST)</li>
 *   <li>{@code fs.server_properties} and {@code fs.connect_properties}
 *       (on-disk file copy when {@code --kafka-config-dir} is set)</li>
 * </ul>
 *
 * <p>Surfaces under {@code kms}:
 * <ul>
 *   <li>{@code placeholders_found}: total {@code ${provider:path}} occurrences</li>
 *   <li>{@code providers_used}: distinct provider names ({@code file},
 *       {@code env}, {@code vault}, {@code aws}, ...)</li>
 *   <li>{@code has_external_provider}: any provider that is not
 *       {@code file} or {@code env} (those still leave the secret on disk
 *       or in the environment)</li>
 *   <li>{@code sensitive_keys_via_provider}: list of sensitive config keys
 *       whose value resolves through a provider</li>
 *   <li>{@code config_providers_declared}: the {@code config.providers}
 *       broker-config value, if present</li>
 * </ul>
 *
 * <p>Runs as a derivation step: it requires no flags of its own. It will
 * still produce empty output if no other collectors ran.
 */
public final class KmsCollector implements Collector {

    /** Config keys whose values should NEVER be plaintext. */
    private static final List<String> SENSITIVE_KEYS = List.of(
        "sasl.jaas.config",
        "ssl.keystore.password",
        "ssl.key.password",
        "ssl.truststore.password",
        "kafkastore.ssl.keystore.password",
        "kafkastore.ssl.key.password",
        "kafkastore.ssl.truststore.password",
        "producer.sasl.jaas.config",
        "consumer.sasl.jaas.config"
    );

    /** Provider names that don't actually externalise the secret. */
    private static final Set<String> NON_EXTERNAL = Set.of("file", "env", "directory");

    private static final Pattern PLACEHOLDER = Pattern.compile(
        "\\$\\{([a-zA-Z][a-zA-Z0-9_-]*):([^}]+)\\}");

    @Override
    public String name() {
        return "kms";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        // Pure-derivation: always considered available so the engine emits
        // `kms.*` even if no source collector ran. CEL conditions still gate
        // on `kms.X.placeholders_found > 0` etc., which evaluates to false
        // on an empty map.
        return true;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        // No I/O: caller passes us pre-collected data via shared state. We
        // don't have a hand-off mechanism for that yet, so this collector
        // returns an empty namespace; the actual aggregation happens in
        // {@link #aggregate(Map)} which {@code Main} calls after every
        // other collector runs.
        return Map.of();
    }

    /**
     * Walk an already-populated data map and emit the {@code kms} namespace.
     * Returns the same map with {@code kms} added so callers can chain.
     */
    public static Map<String, Object> aggregate(Map<String, Object> collected) {
        var providers = new LinkedHashSet<String>();
        var sensitiveKeysViaProvider = new ArrayList<String>();
        long placeholderCount = 0L;
        String configProvidersDeclared = "";

        // Brokers — list of maps each carrying a 'config' string→string map.
        if (collected.get("broker") instanceof List<?> brokers) {
            for (var b : brokers) {
                if (!(b instanceof Map<?, ?> brokerMap)) {
                    continue;
                }
                var cfg = brokerMap.get("config");
                if (cfg instanceof Map<?, ?> cfgMap) {
                    placeholderCount += scan(cfgMap, providers, sensitiveKeysViaProvider);
                    var declared = cfgMap.get("config.providers");
                    if (declared instanceof String s && !s.isBlank()
                        && configProvidersDeclared.isEmpty()) {
                        configProvidersDeclared = s;
                    }
                }
            }
        }

        // Connect connector configs.
        if (collected.get("connect") instanceof Map<?, ?> connect) {
            var ccs = connect.get("connector_configs");
            if (ccs instanceof List<?> list) {
                for (var item : list) {
                    if (!(item instanceof Map<?, ?> entry)) {
                        continue;
                    }
                    var cfg = entry.get("config");
                    if (cfg instanceof Map<?, ?> cfgMap) {
                        placeholderCount += scan(cfgMap, providers, sensitiveKeysViaProvider);
                    }
                }
            }
        }

        // Filesystem-mirrored properties (server.properties / connect-distributed.properties).
        if (collected.get("fs") instanceof Map<?, ?> fs) {
            for (var key : new String[] {"server_properties", "connect_properties"}) {
                var props = fs.get(key);
                if (props instanceof Map<?, ?> map) {
                    placeholderCount += scan(map, providers, sensitiveKeysViaProvider);
                }
            }
        }

        var out = new HashMap<String, Object>();
        out.put("placeholders_found", placeholderCount);
        out.put("providers_used", new ArrayList<>(providers));
        out.put("has_external_provider", providers.stream()
            .anyMatch(p -> !NON_EXTERNAL.contains(p)));
        out.put("sensitive_keys_via_provider", sensitiveKeysViaProvider);
        out.put("config_providers_declared", configProvidersDeclared);
        out.put("collected", true);

        var result = new HashMap<String, Object>(collected);
        result.put("kms", out);
        return result;
    }

    private static long scan(Map<?, ?> cfg, Set<String> providers,
                             List<String> sensitiveKeysViaProvider) {
        long n = 0L;
        for (var e : cfg.entrySet()) {
            if (!(e.getKey() instanceof String key) || !(e.getValue() instanceof String value)) {
                continue;
            }
            var matcher = PLACEHOLDER.matcher(value);
            boolean keyHadPlaceholder = false;
            while (matcher.find()) {
                providers.add(matcher.group(1).toLowerCase(Locale.ROOT));
                n++;
                keyHadPlaceholder = true;
            }
            if (keyHadPlaceholder && SENSITIVE_KEYS.contains(key)
                && !sensitiveKeysViaProvider.contains(key)) {
                sensitiveKeysViaProvider.add(key);
            }
        }
        return n;
    }
}
