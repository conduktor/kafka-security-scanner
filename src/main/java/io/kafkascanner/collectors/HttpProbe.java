package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Shared HTTP helper for ecosystem REST collectors (Connect, Schema Registry,
 * REST Proxy). Captures status, redirect chain, response headers, and parsed
 * JSON body. Surfaces TLS posture so controls can require {@code https}
 * without re-handshaking.
 */
final class HttpProbe {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private HttpProbe() { }

    /** GET {@code url}, return a result map with status / body / TLS info.
     *
     * <p>Always emits the same key set so CEL can rely on `requires_auth`,
     * `anonymous_allowed` and `tls` even when the endpoint is unreachable.
     * Unreachable defaults to {@code requires_auth=false, anonymous_allowed=false}
     * so a security check that demands auth correctly fails an unreachable host
     * rather than silently passing on an absent key.
     */
    static Map<String, Object> get(String url, Duration timeout) {
        var out = new HashMap<String, Object>();
        out.put("url", url);
        out.put("scheme", url.startsWith("https://") ? "https" : "http");
        out.put("tls", url.startsWith("https://"));
        out.put("reachable", false);
        out.put("requires_auth", false);
        out.put("anonymous_allowed", false);
        try {
            var req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(timeout)
                .GET()
                .build();
            var resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            out.put("status", resp.statusCode());
            out.put("reachable", true);
            // 401/403 means auth is required = good; 2xx without auth = bad.
            out.put("requires_auth", resp.statusCode() == 401 || resp.statusCode() == 403);
            out.put("anonymous_allowed", resp.statusCode() >= 200 && resp.statusCode() < 300);
            var body = resp.body();
            try {
                var parsed = JSON.readValue(body, Object.class);
                out.put("body", parsed);
            } catch (Exception ignore) {
                out.put("body_text", body.length() > 4096 ? body.substring(0, 4096) : body);
            }
        } catch (Exception e) {
            out.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return out;
    }
}
