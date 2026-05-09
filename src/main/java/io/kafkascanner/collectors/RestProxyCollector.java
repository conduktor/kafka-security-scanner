package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.Map;

/**
 * Probes Confluent REST Proxy. Pass {@code --rest-proxy-url
 * http://host:8082}. Populates {@code restproxy}.
 */
public final class RestProxyCollector implements Collector {

    @Override
    public String name() {
        return "restproxy";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasRestProxyUrl();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var url = context.restProxyUrl();
        if (url == null) {
            return Map.of();
        }
        var base = url.replaceAll("/+$", "");
        var resp = HttpProbe.get(base + "/topics", context.timeout());
        var out = new HashMap<String, Object>(resp);
        return Map.of("restproxy", out);
    }
}
