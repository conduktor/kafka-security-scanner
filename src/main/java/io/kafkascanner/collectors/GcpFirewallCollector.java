package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Probes GCP Compute firewall rules via {@code compute.googleapis.com} —
 * proves that no firewall rule allows {@code 0.0.0.0/0} on Kafka broker
 * ports {9092, 9094, 9098}.
 *
 * <p>Activated by {@code --gcp-token} (env {@code GCP_TOKEN}) AND
 * {@code --gcp-project}. Token acquisition is left to the operator:
 * <pre>
 *   export GCP_TOKEN="$(gcloud auth print-access-token)"
 *   export GCP_PROJECT="my-project-id"
 * </pre>
 *
 * <p>Surfaces under {@code gcp}:
 * <pre>
 *   gcp.api_reachable             compute.googleapis.com reachable
 *   gcp.api_requires_auth         401 anonymous
 *   gcp.api_authenticated         token accepted
 *   gcp.firewalls_count           total firewall rules in project
 *   gcp.firewalls_open_to_world   any rule INGRESS + ALLOW + 0.0.0.0/0
 *                                 + Kafka broker port range
 *   gcp.open_rules                names of the offending rules
 * </pre>
 */
public final class GcpFirewallCollector implements Collector {

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String API_BASE = "https://compute.googleapis.com/compute/v1";

    private static final int[] BROKER_PORTS = {9092, 9094, 9098};

    @Override
    public String name() {
        return "gcp";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.gcpToken() != null && !context.gcpToken().isBlank();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var token = context.gcpToken();
        var project = context.gcpProject();
        var out = new HashMap<String, Object>();
        out.put("token_present", token != null && !token.isBlank());
        out.put("project", project == null ? "" : project);
        out.put("api_reachable", false);
        out.put("api_status", -1);
        out.put("api_authenticated", false);
        out.put("api_requires_auth", false);
        out.put("firewalls_count", 0L);
        out.put("firewalls_open_to_world", false);
        out.put("open_rules", List.of());

        if (token == null || token.isBlank() || project == null || project.isBlank()) {
            return Map.of("gcp", out);
        }
        var auth = "Bearer " + token;
        var url = API_BASE + "/projects/" + urlEncode(project.trim()) + "/global/firewalls";
        var probe = probe(url, auth, context.timeout());
        out.put("api_reachable", probe.reachable);
        out.put("api_status", probe.status);
        out.put("api_authenticated", probe.status >= 200 && probe.status < 300);
        out.put("api_requires_auth", probe.status == 401 || probe.status == 403);

        if (probe.body instanceof Map<?, ?> body) {
            var items = body.get("items");
            if (items instanceof List<?> list) {
                out.put("firewalls_count", (long) list.size());
                var openRules = new ArrayList<String>();
                for (var rule : list) {
                    if (!(rule instanceof Map<?, ?> ruleMap)) {
                        continue;
                    }
                    if (isWorldOpenOnBrokerPort(ruleMap)) {
                        var name = ruleMap.get("name");
                        openRules.add(name == null ? "?" : String.valueOf(name));
                    }
                }
                out.put("firewalls_open_to_world", !openRules.isEmpty());
                out.put("open_rules", openRules);
            }
        }
        return Map.of("gcp", out);
    }

    /**
     * GCP firewall rule: ingress, allow action, sourceRanges contains
     * 0.0.0.0/0, and at least one allowed entry covers a broker port.
     */
    private static boolean isWorldOpenOnBrokerPort(Map<?, ?> rule) {
        var direction = rule.get("direction") == null ? "INGRESS" : String.valueOf(rule.get("direction"));
        if (!"INGRESS".equalsIgnoreCase(direction)) {
            return false;
        }
        var disabled = rule.get("disabled");
        if (Boolean.TRUE.equals(disabled)) {
            return false;
        }
        var sources = rule.get("sourceRanges");
        boolean openSource = false;
        if (sources instanceof List<?> list) {
            for (var s : list) {
                if ("0.0.0.0/0".equals(String.valueOf(s))) {
                    openSource = true;
                    break;
                }
            }
        }
        if (!openSource) {
            return false;
        }
        var allowed = rule.get("allowed");
        if (!(allowed instanceof List<?> allowList)) {
            return false;
        }
        for (var entry : allowList) {
            if (!(entry instanceof Map<?, ?> entryMap)) {
                continue;
            }
            var protocol = entryMap.get("IPProtocol") == null ? "" : String.valueOf(entryMap.get("IPProtocol"))
                .toLowerCase(java.util.Locale.ROOT);
            if (!protocol.equals("tcp") && !protocol.equals("all")) {
                continue;
            }
            var ports = entryMap.get("ports");
            // protocol=all OR no ports specified -> all ports open
            if (ports == null || (ports instanceof List<?> pl && pl.isEmpty())
                || "all".equals(protocol)) {
                return true;
            }
            if (ports instanceof List<?> portList) {
                for (var p : portList) {
                    if (portRangeCoversBrokerPort(String.valueOf(p))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean portRangeCoversBrokerPort(String spec) {
        try {
            int lo;
            int hi;
            if (spec.contains("-")) {
                var parts = spec.split("-", 2);
                lo = Integer.parseInt(parts[0].trim());
                hi = Integer.parseInt(parts[1].trim());
            } else {
                lo = Integer.parseInt(spec.trim());
                hi = lo;
            }
            for (int p : BROKER_PORTS) {
                if (p >= lo && p <= hi) {
                    return true;
                }
            }
        } catch (NumberFormatException ignore) {
            // skip malformed
        }
        return false;
    }

    private record Probe(boolean reachable, int status, @Nullable Object body) { }

    private static Probe probe(String url, @Nullable String authHeader, Duration timeout) {
        try {
            var b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(timeout)
                .GET();
            if (authHeader != null) {
                b.header("Authorization", authHeader);
            }
            var resp = CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
            Object parsed = null;
            try {
                parsed = JSON.readValue(resp.body(), Object.class);
            } catch (Exception ignore) {
                // not JSON
            }
            return new Probe(true, resp.statusCode(), parsed);
        } catch (Exception e) {
            return new Probe(false, -1, null);
        }
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8)
            .replace("+", "%20");
    }
}
