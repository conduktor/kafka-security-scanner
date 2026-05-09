package io.kafkascanner.collectors;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Pulls alerting rules from a Prometheus-compatible endpoint
 * ({@code /api/v1/rules}).
 *
 * <p>Populates {@code alerts} on the scan data so MON / AUDIT controls can
 * write conditions like
 * {@code alerts.has_auth_failure_rule || alerts.has_acl_change_rule}.
 *
 * <p>Boolean shortcuts are computed by case-insensitive match against rule
 * name + query string. They are intentionally permissive (substring) —
 * a healthy alerting setup will match more than one trigger token.
 */
public final class AlertRuleCollector implements Collector {

    @Override
    public String name() {
        return "alerts";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasPrometheusUrl();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var url = context.prometheusUrl();
        if (url == null) {
            return Map.of();
        }
        var base = url.replaceAll("/+$", "");
        var probe = HttpProbe.get(base + "/api/v1/rules", context.timeout());
        var out = new HashMap<String, Object>();
        out.put("url", base);
        out.put("scheme", probe.get("scheme"));
        out.put("tls", probe.get("tls"));
        out.put("reachable", probe.get("reachable"));
        out.put("requires_auth", probe.get("requires_auth"));

        var rules = parseRules(probe.get("body"));
        out.put("rules", rules);
        out.put("rule_count", (long) rules.size());

        // Pre-compute the 5 shortcuts MON / AUDIT controls want.
        out.put("has_auth_failure_rule",
            anyMatch(rules, "auth_fail", "auth-fail", "authentication", "failed_authent",
                "kafka_auth_failures", "sasl_auth"));
        out.put("has_acl_change_rule",
            anyMatch(rules, "acl_change", "acl_modif", "acl_audit", "acl_denied"));
        out.put("has_quota_breach_rule",
            anyMatch(rules, "quota_breach", "quota_violation", "throttle_time",
                "quota_exceeded"));
        out.put("has_replication_health_rule",
            anyMatch(rules, "under_replicated", "underreplicated", "replication_lag",
                "isr_shrink", "offline_partitions"));
        out.put("has_anomaly_rule",
            anyMatch(rules, "anomaly", "outlier", "spike", "deviation", "stddev"));
        out.put("has_consumer_lag_rule",
            anyMatch(rules, "consumer_lag", "records_lag", "kafka_lag"));

        return Map.of("alerts", out);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> parseRules(@org.checkerframework.checker.nullness.qual.Nullable Object body) {
        var out = new ArrayList<Map<String, Object>>();
        if (!(body instanceof Map<?, ?> root)) {
            return out;
        }
        var data = root.get("data");
        if (!(data instanceof Map<?, ?> dataMap)) {
            return out;
        }
        var groups = dataMap.get("groups");
        if (!(groups instanceof List<?> list)) {
            return out;
        }
        for (var g : list) {
            if (!(g instanceof Map<?, ?> group)) {
                continue;
            }
            var groupName = String.valueOf(group.get("name"));
            var groupRules = group.get("rules");
            if (!(groupRules instanceof List<?> ruleList)) {
                continue;
            }
            for (var r : ruleList) {
                if (!(r instanceof Map<?, ?> rule)) {
                    continue;
                }
                var entry = new HashMap<String, Object>();
                entry.put("group", groupName);
                entry.put("name", String.valueOf(rule.get("name")));
                entry.put("type", String.valueOf(rule.get("type")));
                entry.put("query", String.valueOf(rule.get("query")));
                var labels = rule.get("labels");
                if (labels instanceof Map<?, ?> lm) {
                    entry.put("labels", lm);
                }
                out.add(entry);
            }
        }
        return out;
    }

    private static boolean anyMatch(List<Map<String, Object>> rules, String... needles) {
        for (var r : rules) {
            var hay = (String.valueOf(r.get("name"))
                + " " + String.valueOf(r.get("query")))
                .toLowerCase(Locale.ROOT);
            for (var n : needles) {
                if (hay.contains(n)) {
                    return true;
                }
            }
        }
        return false;
    }
}
