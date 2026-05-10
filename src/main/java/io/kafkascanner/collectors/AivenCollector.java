package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Probes the Aiven control plane (https://api.aiven.io). Activates when
 * {@code --aiven-token} (env {@code AIVEN_TOKEN}) is set OR when the detected
 * flavor is {@link io.kafkascanner.flavor.FlavorDetector#AIVEN}.
 *
 * <p>Endpoints exercised:
 * <ul>
 *   <li>{@code GET /v1/me} — auth posture (200 with token, 401 without)</li>
 *   <li>{@code GET /v1/project/{p}/service/{s}} — service spec (encryption,
 *       ip_filter list, plan, cloud) when {@code --aiven-project} and
 *       {@code --aiven-service} are passed</li>
 * </ul>
 *
 * <p>Surfaces under {@code aiven}:
 * <pre>
 *   aiven.api_reachable        api.aiven.io is HTTP-reachable
 *   aiven.api_requires_auth    /v1/me without token returns 401/403
 *   aiven.api_authenticated    token present and accepted
 *   aiven.service_present      project+service args provided AND fetched 200
 *   aiven.plan                 service plan name (business-4, premium-8, ...)
 *   aiven.cloud                cloud provider (aws-eu-west-1, gcp-..., ...)
 *   aiven.ip_filter_count      number of CIDR rules (0 = wide open)
 *   aiven.ip_filter_open       any rule has 0.0.0.0/0
 * </pre>
 */
public final class AivenCollector implements Collector {

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String API_BASE = "https://api.aiven.io";

    @Override
    public String name() {
        return "aiven";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        var token = context.aivenToken();
        var hasToken = token != null && !token.isBlank();
        var aivenFlavor = "aiven".equals(context.kafkaFlavor());
        return hasToken || aivenFlavor;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();
        out.put("flavor_detected", "aiven".equals(context.kafkaFlavor()));
        var token = context.aivenToken();
        out.put("token_present", token != null && !token.isBlank());

        var auth = (token != null && !token.isBlank()) ? "Bearer " + token : null;

        var meProbe = probe(API_BASE + "/v1/me", auth, context.timeout());
        out.put("api_reachable", meProbe.reachable);
        out.put("api_status", meProbe.status);
        out.put("api_authenticated",
            meProbe.status >= 200 && meProbe.status < 300);
        // Aiven returns 401 anonymous; some endpoints answer 403 if the
        // token lacks permissions — treat both as "auth required".
        out.put("api_requires_auth",
            meProbe.status == 401 || meProbe.status == 403);

        out.put("service_present", false);
        out.put("plan", "");
        out.put("cloud", "");
        out.put("ip_filter_count", 0L);
        out.put("ip_filter_open", false);
        out.put("kafka_authentication_methods", List.of());

        var project = context.aivenProject();
        var service = context.aivenService();
        if (auth != null && project != null && !project.isBlank()
            && service != null && !service.isBlank()) {
            var url = API_BASE + "/v1/project/" + urlEncode(project)
                + "/service/" + urlEncode(service);
            var svcProbe = probe(url, auth, context.timeout());
            out.put("service_status", svcProbe.status);
            if (svcProbe.body instanceof Map<?, ?> body) {
                var svc = body.get("service");
                if (svc instanceof Map<?, ?> svcMap) {
                    out.put("service_present", true);
                    var plan = svcMap.get("plan");
                    out.put("plan", plan == null ? "" : String.valueOf(plan));
                    var cloud = svcMap.get("cloud");
                    out.put("cloud", cloud == null ? "" : String.valueOf(cloud));

                    var userConfig = svcMap.get("user_config");
                    if (userConfig instanceof Map<?, ?> uc) {
                        var ipFilter = uc.get("ip_filter");
                        if (ipFilter instanceof List<?> filters) {
                            out.put("ip_filter_count", (long) filters.size());
                            boolean open = false;
                            for (var f : filters) {
                                if (f instanceof String s && s.contains("0.0.0.0/0")) {
                                    open = true;
                                    break;
                                }
                                if (f instanceof Map<?, ?> fm) {
                                    var nw = fm.get("network") == null ? ""
                                        : String.valueOf(fm.get("network"));
                                    if (nw.contains("0.0.0.0/0")) {
                                        open = true;
                                        break;
                                    }
                                }
                            }
                            out.put("ip_filter_open", open);
                        }
                        var kafka = uc.get("kafka_authentication_methods");
                        if (kafka instanceof Map<?, ?> km) {
                            var methods = new java.util.ArrayList<String>();
                            for (var e : km.entrySet()) {
                                if (Boolean.TRUE.equals(e.getValue())
                                    && e.getKey() instanceof String key) {
                                    methods.add(key.toLowerCase(Locale.ROOT));
                                }
                            }
                            out.put("kafka_authentication_methods", methods);
                        }
                    }
                }
            }
        }
        return Map.of("aiven", out);
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
