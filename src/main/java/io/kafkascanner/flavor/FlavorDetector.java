package io.kafkascanner.flavor;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Detects the Kafka deployment flavor from a bootstrap hostname. Flavor knowledge lets
 * the policy engine short-circuit controls that are guaranteed by a managed-service SLA
 * (encryption-at-rest on Confluent Cloud, EBS encryption on MSK, etc.) instead of
 * silently passing them based on a missing config field.
 */
public final class FlavorDetector {

    public static final String VANILLA = "vanilla";
    public static final String CONFLUENT_CLOUD = "confluent-cloud";
    public static final String AWS_MSK = "aws-msk";
    public static final String AIVEN = "aiven";
    public static final String REDPANDA_CLOUD = "redpanda-cloud";
    public static final String AZURE_EVENTHUBS = "azure-eventhubs";
    public static final String WARPSTREAM = "warpstream";
    public static final String CONDUKTOR_GATEWAY = "conduktor-gateway";

    private static final List<Rule> RULES = List.of(
        new Rule(CONFLUENT_CLOUD, Pattern.compile(".*\\.confluent\\.cloud$", Pattern.CASE_INSENSITIVE)),
        new Rule(AWS_MSK, Pattern.compile("^(b-\\d+\\.)?[^.]+\\.[a-z0-9-]+\\.kafka(-serverless)?\\.[a-z0-9-]+\\.amazonaws\\.com$",
            Pattern.CASE_INSENSITIVE)),
        new Rule(AIVEN, Pattern.compile(".*\\.aivencloud\\.com$", Pattern.CASE_INSENSITIVE)),
        new Rule(REDPANDA_CLOUD, Pattern.compile(".*\\.cloud\\.redpanda\\.com$", Pattern.CASE_INSENSITIVE)),
        new Rule(AZURE_EVENTHUBS, Pattern.compile(".*\\.servicebus\\.windows\\.net$", Pattern.CASE_INSENSITIVE)),
        new Rule(WARPSTREAM, Pattern.compile(".*\\.warpstream\\.com$", Pattern.CASE_INSENSITIVE)),
        new Rule(CONDUKTOR_GATEWAY, Pattern.compile(".*\\.conduktor\\.(io|cloud)$", Pattern.CASE_INSENSITIVE))
    );

    private FlavorDetector() { }

    public record Detection(String flavor, String source) { }

    /**
     * Resolve the flavor. Returns the explicit override if non-blank, otherwise inspects
     * the first hostname in the bootstrap string. Falls back to {@link #VANILLA}.
     */
    public static Detection detect(String bootstrap, @Nullable String override) {
        if (override != null && !override.isBlank()) {
            return new Detection(override.trim().toLowerCase(Locale.ROOT), "override");
        }
        var host = firstHost(bootstrap);
        if (host == null) {
            return new Detection(VANILLA, "default");
        }
        for (var rule : RULES) {
            if (rule.pattern.matcher(host).matches()) {
                return new Detection(rule.flavor, "hostname:" + host);
            }
        }
        return new Detection(VANILLA, "hostname:" + host);
    }

    private static @Nullable String firstHost(String bootstrap) {
        if (bootstrap == null || bootstrap.isBlank()) {
            return null;
        }
        var first = bootstrap.split(",", 2)[0].trim();
        var colon = first.lastIndexOf(':');
        var host = colon > 0 ? first.substring(0, colon) : first;
        return host.isBlank() ? null : host;
    }

    private record Rule(String flavor, Pattern pattern) { }
}
