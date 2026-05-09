package io.kafkascanner.collectors;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Probes a Kafka Connect worker REST API. Populates {@code connect} on the scan
 * data. Pass {@code --connect-url http://host:8083}.
 *
 * <p>Surfaces:
 * <ul>
 *   <li>{@code reachable} — handshake success</li>
 *   <li>{@code tls} / {@code scheme} — http vs https</li>
 *   <li>{@code requires_auth} — 401/403 on /</li>
 *   <li>{@code anonymous_allowed} — 2xx on / without creds</li>
 *   <li>{@code connectors} — list returned by /connectors</li>
 *   <li>{@code mm2_connector_present} — at least one MirrorSourceConnector</li>
 *   <li>{@code plugin_count} / {@code plugins} from /connector-plugins</li>
 * </ul>
 */
public final class ConnectCollector implements Collector {

    @Override
    public String name() {
        return "connect";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasConnectUrl();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var url = context.connectUrl();
        if (url == null) {
            return Map.of();
        }
        var base = url.replaceAll("/+$", "");
        var out = new HashMap<String, Object>(HttpProbe.get(base + "/", context.timeout()));

        var connectorsResp = HttpProbe.get(base + "/connectors", context.timeout());
        var connectorsBody = connectorsResp.get("body");
        var names = new ArrayList<String>();
        if (connectorsBody instanceof List<?> list) {
            for (var item : list) {
                if (item instanceof String s) {
                    names.add(s);
                }
            }
        }
        out.put("connectors", names);
        out.put("connector_count", (long) names.size());

        // Per-connector deep dive: GET /connectors/{name}/config feeds MM2-001,
        // AUDIT-008, DATA-007/010, OPS-010 with real configuration evidence.
        var configs = new ArrayList<Map<String, Object>>();
        boolean mm2Secure = !names.isEmpty();
        boolean anyMm2 = false;
        boolean anyMaskTransform = false;
        boolean anyDlq = false;
        boolean anyTopicAuditable = false;
        for (var name : names) {
            var cfgResp = HttpProbe.get(base + "/connectors/" + urlEncode(name) + "/config",
                context.timeout());
            var cfgBody = cfgResp.get("body");
            var entry = new HashMap<String, Object>();
            entry.put("name", name);
            entry.put("reachable", cfgResp.get("reachable"));
            if (cfgBody instanceof Map<?, ?> raw) {
                var cfg = new HashMap<String, String>();
                for (var k : raw.keySet()) {
                    if (k instanceof String key) {
                        var v = raw.get(key);
                        cfg.put(key, v == null ? "" : String.valueOf(v));
                    }
                }
                entry.put("config", cfg);
                entry.put("connector_class", cfg.getOrDefault("connector.class", ""));

                var transforms = parseList(cfg.getOrDefault("transforms", ""));
                entry.put("transforms", transforms);
                boolean masks = transforms.stream().anyMatch(t -> {
                    var typeKey = "transforms." + t + ".type";
                    var clazz = cfg.getOrDefault(typeKey, "").toLowerCase(Locale.ROOT);
                    return clazz.contains("maskfield") || clazz.contains("regexrouter")
                        || clazz.contains("replacefield") || clazz.contains("hoistfield");
                });
                entry.put("has_mask_transform", masks);
                if (masks) {
                    anyMaskTransform = true;
                }

                var tolerance = cfg.getOrDefault("errors.tolerance", "");
                entry.put("errors_tolerance", tolerance);
                var dlq = cfg.getOrDefault("errors.deadletterqueue.topic.name", "");
                entry.put("errors_dlq_topic", dlq);
                if (!dlq.isBlank()) {
                    anyDlq = true;
                }

                var classLower = String.valueOf(entry.get("connector_class")).toLowerCase(Locale.ROOT);
                if (classLower.contains("mirror")) {
                    anyMm2 = true;
                    var srcSec = cfg.getOrDefault("source.cluster.security.protocol", "")
                        .toUpperCase(Locale.ROOT);
                    var tgtSec = cfg.getOrDefault("target.cluster.security.protocol", "")
                        .toUpperCase(Locale.ROOT);
                    boolean secure = (srcSec.contains("SSL") || srcSec.contains("SASL"))
                        && (tgtSec.contains("SSL") || tgtSec.contains("SASL"));
                    entry.put("mm2_secure", secure);
                    if (!secure) {
                        mm2Secure = false;
                    }
                }

                if (cfg.containsKey("topics") || cfg.containsKey("topics.regex")) {
                    anyTopicAuditable = true;
                }
            } else {
                entry.put("config", Map.of());
                entry.put("transforms", List.of());
                entry.put("has_mask_transform", false);
                entry.put("errors_tolerance", "");
                entry.put("errors_dlq_topic", "");
            }
            configs.add(entry);
        }

        out.put("connector_configs", configs);
        out.put("mm2_connector_present", anyMm2);
        out.put("mm2_all_secure", anyMm2 && mm2Secure);
        out.put("any_mask_transform", anyMaskTransform);
        out.put("any_dlq_topic_configured", anyDlq);
        out.put("any_connector_topic_listed", anyTopicAuditable);

        var pluginsResp = HttpProbe.get(base + "/connector-plugins", context.timeout());
        var plugins = pluginsResp.get("body");
        if (plugins instanceof List<?> list) {
            out.put("plugin_count", (long) list.size());
        } else {
            out.put("plugin_count", 0L);
        }

        return Map.of("connect", out);
    }

    private static List<String> parseList(String csv) {
        var out = new ArrayList<String>();
        if (csv == null || csv.isBlank()) {
            return out;
        }
        for (var part : csv.split(",")) {
            var t = part.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8)
            .replace("+", "%20");
    }
}
