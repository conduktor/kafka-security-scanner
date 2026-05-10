package io.kafkascanner.collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Probes the Redpanda Cloud control plane (https://api.redpanda.com).
 * Activated by {@code --rp-token} (env {@code RP_TOKEN}) OR when the detected
 * flavor is {@link io.kafkascanner.flavor.FlavorDetector#REDPANDA_CLOUD}.
 *
 * <p>Endpoints exercised:
 * <ul>
 *   <li>{@code GET /v1beta2/users} — auth posture probe (401 anonymous).</li>
 *   <li>{@code GET /v1beta2/clusters/{id}} when {@code --rp-cluster-id} set —
 *       reads cluster spec for connection_type / encryption / region.</li>
 * </ul>
 *
 * <p>Surfaces under {@code rpcloud}:
 * <pre>
 *   rpcloud.api_reachable        TCP/HTTPS reachable
 *   rpcloud.api_requires_auth    401/403 anonymous
 *   rpcloud.api_authenticated    token accepted
 *   rpcloud.cluster_present      cluster spec fetched 200
 *   rpcloud.connection_type      "private" / "public" (BYOC vs serverless)
 *   rpcloud.region
 *   rpcloud.is_serverless        cluster type substring match
 * </pre>
 */
public final class RedpandaCloudCollector implements Collector {

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String API_BASE = "https://api.redpanda.com";

    @Override
    public String name() {
        return "rpcloud";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        var token = context.rpToken();
        var hasToken = token != null && !token.isBlank();
        var rpFlavor = "redpanda-cloud".equals(context.kafkaFlavor());
        return hasToken || rpFlavor;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();
        out.put("flavor_detected", "redpanda-cloud".equals(context.kafkaFlavor()));
        var token = context.rpToken();
        out.put("token_present", token != null && !token.isBlank());

        var auth = (token != null && !token.isBlank()) ? "Bearer " + token : null;

        var meProbe = probe(API_BASE + "/v1beta2/users", auth, context.timeout());
        out.put("api_reachable", meProbe.reachable);
        out.put("api_status", meProbe.status);
        out.put("api_authenticated", meProbe.status >= 200 && meProbe.status < 300);
        out.put("api_requires_auth", meProbe.status == 401 || meProbe.status == 403);

        out.put("cluster_present", false);
        out.put("connection_type", "");
        out.put("region", "");
        out.put("is_serverless", false);

        var configuredClusterId = context.rpClusterId();
        if (auth != null && configuredClusterId != null && !configuredClusterId.isBlank()) {
            var url = API_BASE + "/v1beta2/clusters/" + urlEncode(configuredClusterId.trim());
            var clusterProbe = probe(url, auth, context.timeout());
            out.put("cluster_status", clusterProbe.status);
            if (clusterProbe.body instanceof Map<?, ?> body) {
                Object spec = body.containsKey("cluster") ? body.get("cluster") : body;
                if (spec instanceof Map<?, ?> specMap) {
                    out.put("cluster_present", true);
                    var ct = specMap.get("connection_type");
                    out.put("connection_type", ct == null ? ""
                        : String.valueOf(ct).toLowerCase(Locale.ROOT));
                    var region = specMap.get("region");
                    out.put("region", region == null ? "" : String.valueOf(region));
                    var type = specMap.get("type");
                    if (type != null) {
                        out.put("is_serverless", String.valueOf(type)
                            .toLowerCase(Locale.ROOT).contains("serverless"));
                    }
                }
            }
        }
        return Map.of("rpcloud", out);
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
            } catch (JsonProcessingException e) {
                System.err.println("[rpcloud] response JSON parse failed: " + e.getOriginalMessage());
            }
            return new Probe(true, resp.statusCode(), parsed);
        } catch (IOException | IllegalArgumentException e) {
            System.err.println("[rpcloud] probe failed: " + e.getMessage());
            return new Probe(false, -1, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("[rpcloud] probe interrupted: " + e.getMessage());
            return new Probe(false, -1, null);
        }
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8)
            .replace("+", "%20");
    }
}
