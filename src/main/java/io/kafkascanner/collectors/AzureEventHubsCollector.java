package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Probes Azure Event Hubs via the ARM REST API
 * (https://management.azure.com).
 *
 * <p>Activated by {@code --azure-token} (env {@code AZURE_TOKEN}) or when the
 * detected flavor is
 * {@link io.kafkascanner.flavor.FlavorDetector#AZURE_EVENTHUBS}.
 *
 * <p>Token acquisition is left to the operator:
 * <pre>
 *   export AZURE_TOKEN="$(az account get-access-token \
 *     --resource https://management.azure.com --query accessToken -o tsv)"
 * </pre>
 *
 * <p>When {@code --azure-subscription-id}, {@code --azure-resource-group}, and
 * {@code --azure-namespace} are all set, the collector fetches the namespace
 * spec and surfaces the security-relevant fields:
 * <pre>
 *   azure.api_reachable           management.azure.com reachable
 *   azure.api_requires_auth       401 anonymous
 *   azure.api_authenticated       token accepted
 *   azure.namespace_present       spec fetched 200
 *   azure.minimum_tls_version     "1.0" / "1.1" / "1.2"
 *   azure.public_network_access   "Enabled" / "Disabled"
 *   azure.private_endpoints_count
 *   azure.zone_redundant
 *   azure.disable_local_auth      true = SAS keys disabled, AAD only
 * </pre>
 */
public final class AzureEventHubsCollector implements Collector {

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final String API_BASE = "https://management.azure.com";

    private static final String API_VERSION = "2024-01-01";

    @Override
    public String name() {
        return "azure";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        var token = context.azureToken();
        var hasToken = token != null && !token.isBlank();
        var azureFlavor = "azure-eventhubs".equals(context.kafkaFlavor());
        return hasToken || azureFlavor;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();
        out.put("flavor_detected", "azure-eventhubs".equals(context.kafkaFlavor()));
        var token = context.azureToken();
        out.put("token_present", token != null && !token.isBlank());

        var auth = (token != null && !token.isBlank()) ? "Bearer " + token : null;

        // Auth posture: list-subscriptions endpoint is the canonical anon-401 probe
        var meProbe = probe(API_BASE + "/subscriptions?api-version=2022-12-01",
            auth, context.timeout());
        out.put("api_reachable", meProbe.reachable);
        out.put("api_status", meProbe.status);
        out.put("api_authenticated", meProbe.status >= 200 && meProbe.status < 300);
        out.put("api_requires_auth", meProbe.status == 401 || meProbe.status == 403);

        out.put("namespace_present", false);
        out.put("minimum_tls_version", "");
        out.put("public_network_access", "");
        out.put("private_endpoints_count", 0L);
        out.put("zone_redundant", false);
        out.put("disable_local_auth", false);

        var sub = context.azureSubscriptionId();
        var rg = context.azureResourceGroup();
        var ns = context.azureNamespace();
        if (auth != null && sub != null && !sub.isBlank()
            && rg != null && !rg.isBlank()
            && ns != null && !ns.isBlank()) {
            var url = API_BASE + "/subscriptions/" + urlEncode(sub.trim())
                + "/resourceGroups/" + urlEncode(rg.trim())
                + "/providers/Microsoft.EventHub/namespaces/" + urlEncode(ns.trim())
                + "?api-version=" + API_VERSION;
            var nsProbe = probe(url, auth, context.timeout());
            out.put("namespace_status", nsProbe.status);
            if (nsProbe.body instanceof Map<?, ?> body) {
                var props = body.get("properties");
                if (props instanceof Map<?, ?> propsMap) {
                    out.put("namespace_present", true);
                    var minTls = propsMap.get("minimumTlsVersion");
                    if (minTls != null) {
                        out.put("minimum_tls_version", String.valueOf(minTls));
                    }
                    var pna = propsMap.get("publicNetworkAccess");
                    if (pna != null) {
                        out.put("public_network_access", String.valueOf(pna));
                    }
                    var pe = propsMap.get("privateEndpointConnections");
                    if (pe instanceof java.util.List<?> list) {
                        out.put("private_endpoints_count", (long) list.size());
                    }
                    var zr = propsMap.get("zoneRedundant");
                    out.put("zone_redundant", Boolean.TRUE.equals(zr));
                    var dla = propsMap.get("disableLocalAuth");
                    out.put("disable_local_auth", Boolean.TRUE.equals(dla));
                }
            }
        }
        return Map.of("azure", out);
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
