package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.List;
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
        var connectors = connectorsResp.get("body");
        if (connectors instanceof List<?> list) {
            out.put("connectors", list);
            out.put("connector_count", (long) list.size());
            out.put("mm2_connector_present", list.stream().anyMatch(c ->
                c instanceof String s && s.toLowerCase(java.util.Locale.ROOT).contains("mirror")));
        } else {
            out.put("connectors", List.of());
            out.put("connector_count", 0L);
            out.put("mm2_connector_present", false);
        }

        var pluginsResp = HttpProbe.get(base + "/connector-plugins", context.timeout());
        var plugins = pluginsResp.get("body");
        if (plugins instanceof List<?> list) {
            out.put("plugin_count", (long) list.size());
        } else {
            out.put("plugin_count", 0L);
        }

        return Map.of("connect", out);
    }
}
