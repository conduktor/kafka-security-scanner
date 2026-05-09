package io.kafkascanner.collectors;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Probes Confluent Cloud control-plane endpoints. Activates when
 * {@code --cc-api-key} and {@code --cc-api-secret} are passed (or when the
 * detected flavor is {@link io.kafkascanner.flavor.FlavorDetector#CONFLUENT_CLOUD}
 * and the env vars {@code CC_API_KEY} / {@code CC_API_SECRET} are set).
 *
 * <p>Two endpoints exercised:
 * <ul>
 *   <li>{@code GET https://api.confluent.cloud/cmk/v2/clusters/{lkc-id}} — fetches
 *       cluster spec including encryption settings and network configuration.</li>
 *   <li>{@code GET https://api.telemetry.confluent.cloud/v2/metrics/cloud/descriptors/metrics}
 *       — proves the Metrics API is reachable and that the supplied API key has
 *       the {@code MetricsViewer} role.</li>
 * </ul>
 *
 * <p>If {@code --cc-cluster-id} is omitted, the collector still verifies the
 * REST API responds 401/403 to anonymous calls and 200 to authenticated calls.
 */
public final class ConfluentCloudCollector implements Collector {

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private static final com.fasterxml.jackson.databind.ObjectMapper JSON =
        new com.fasterxml.jackson.databind.ObjectMapper();

    private static final String REST_BASE = "https://api.confluent.cloud";
    private static final String METRICS_BASE = "https://api.telemetry.confluent.cloud";

    @Override
    public String name() {
        return "confluentcloud";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        // Activate when the operator hands over creds OR the bootstrap is on a CC host.
        var hasCreds = context.ccApiKey() != null && !context.ccApiKey().isBlank()
            && context.ccApiSecret() != null && !context.ccApiSecret().isBlank();
        var ccFlavor = "confluent-cloud".equals(context.kafkaFlavor());
        return hasCreds || ccFlavor;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();
        out.put("flavor_detected", "confluent-cloud".equals(context.kafkaFlavor()));

        var auth = buildAuthHeader(context.ccApiKey(), context.ccApiSecret());
        out.put("api_key_present", auth != null);

        // Probe the REST API root with whatever creds we have.
        var listClusters = probe(REST_BASE + "/cmk/v2/clusters?page_size=1",
            auth, context.timeout());
        out.put("api_reachable", listClusters.reachable);
        out.put("api_status", listClusters.status);
        out.put("api_authenticated", listClusters.status >= 200 && listClusters.status < 300);
        out.put("api_requires_auth", listClusters.status == 401 || listClusters.status == 403);

        // Metrics API: hit the query endpoint with an empty POST. The descriptors
        // endpoint is public so probing it doesn't prove auth posture; the query
        // endpoint demands credentials and returns 401/403 anonymous.
        var metricsProbe = postProbe(METRICS_BASE + "/v2/metrics/cloud/query",
            "{}", auth, context.timeout());
        out.put("metrics_api_reachable", metricsProbe.reachable);
        out.put("metrics_api_status", metricsProbe.status);
        out.put("metrics_api_authenticated",
            metricsProbe.status >= 200 && metricsProbe.status < 300);
        out.put("metrics_api_requires_auth",
            metricsProbe.status == 401 || metricsProbe.status == 403);

        // If we have creds AND a cluster id, fetch the spec so encryption /
        // network / cluster_type controls have something to read.
        if (auth != null && context.ccClusterId() != null
            && !context.ccClusterId().isBlank()) {
            var clusterId = context.ccClusterId().trim();
            var clusterProbe = probe(
                REST_BASE + "/cmk/v2/clusters/" + clusterId,
                auth, context.timeout());
            out.put("cluster_id", clusterId);
            out.put("cluster_status", clusterProbe.status);
            out.put("cluster_authenticated",
                clusterProbe.status >= 200 && clusterProbe.status < 300);
            if (clusterProbe.body instanceof Map<?, ?> body) {
                var spec = body.get("spec");
                if (spec instanceof Map<?, ?> specMap) {
                    var availability = specMap.get("availability");
                    out.put("availability", String.valueOf(availability));
                    var cloud = specMap.get("cloud");
                    out.put("cloud", String.valueOf(cloud));
                    var region = specMap.get("region");
                    out.put("region", String.valueOf(region));
                    var config = specMap.get("config");
                    if (config instanceof Map<?, ?> configMap) {
                        var kind = String.valueOf(configMap.get("kind")).toLowerCase(Locale.ROOT);
                        out.put("cluster_type", kind);
                        out.put("dedicated_or_enterprise",
                            kind.contains("dedicated") || kind.contains("enterprise"));
                    }
                    // network field present means BYOK / private link / peered VPC.
                    out.put("private_networking", specMap.containsKey("network")
                        && specMap.get("network") != null);
                    var encryption = specMap.get("byok_key");
                    out.put("byok_encryption_at_rest",
                        encryption != null && !"null".equals(String.valueOf(encryption)));
                }
            }
        } else {
            out.put("cluster_id", "");
            out.put("dedicated_or_enterprise", false);
            out.put("private_networking", false);
            out.put("byok_encryption_at_rest", false);
        }

        return Map.of("cc", out);
    }

    private static @Nullable String buildAuthHeader(@Nullable String key, @Nullable String secret) {
        if (key == null || key.isBlank() || secret == null || secret.isBlank()) {
            return null;
        }
        var raw = (key.trim() + ":" + secret.trim()).getBytes(StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(raw);
    }

    private record Probe(boolean reachable, int status, @Nullable Object body) { }

    private static Probe probe(String url, @Nullable String authHeader, Duration timeout) {
        var builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .GET();
        return send(builder, authHeader);
    }

    private static Probe postProbe(String url, String body, @Nullable String authHeader,
                                    Duration timeout) {
        var builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
        return send(builder, authHeader);
    }

    private static Probe send(HttpRequest.Builder builder, @Nullable String authHeader) {
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        try {
            var resp = CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
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
}
