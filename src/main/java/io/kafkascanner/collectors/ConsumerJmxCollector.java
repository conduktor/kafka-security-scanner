package io.kafkascanner.collectors;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Polls consumer JMX endpoints for {@code records-lag-max} per client-id.
 *
 * <p>Pass {@code --consumer-jmx-host-ports a:1099,b:1099,...}. Returns the
 * worst lag across every (target, client-id) combination so MON-005 can
 * compare against an SLO.
 *
 * <p>Why a separate collector? {@link JmxCollector} targets the broker JVM;
 * consumer lag MBeans live on the consumer JVM, which is rarely the same
 * host. We expose results under the {@code consumer_jmx} namespace so
 * controls don't have to disambiguate.
 */
public final class ConsumerJmxCollector implements Collector {

    @Override
    public String name() {
        return "consumerjmx";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.consumerJmxHostPorts() != null
            && !context.consumerJmxHostPorts().isBlank();
    }

    @Override
    @SuppressWarnings("BanJNDI")
    public Map<String, Object> collect(CollectorContext context) {
        var raw = context.consumerJmxHostPorts();
        if (raw == null || raw.isBlank()) {
            return Map.of();
        }
        var targets = new ArrayList<String>();
        for (var t : raw.split(",")) {
            var hp = t.trim();
            if (!hp.isEmpty()) {
                targets.add(hp);
            }
        }
        long worstLag = -1L;
        var perTarget = new LinkedHashMap<String, Object>();
        var unreachable = new ArrayList<String>();
        for (var hp : targets) {
            var url = "service:jmx:rmi:///jndi/rmi://" + hp + "/jmxrmi";
            try (JMXConnector conn = JmxConnectorSupport.connect(url, context.timeout())) {
                var mbsc = conn.getMBeanServerConnection();
                var lags = readClientLag(mbsc);
                perTarget.put(hp, lags);
                for (var v : lags.values()) {
                    if (v != null && v > worstLag) {
                        worstLag = v;
                    }
                }
            } catch (IOException e) {
                unreachable.add(hp);
            }
        }
        var out = new HashMap<String, Object>();
        out.put("targets", targets);
        out.put("targets_reachable", targets.size() - unreachable.size());
        out.put("targets_unreachable", unreachable);
        out.put("lag_per_target", perTarget);
        out.put("lag_max", worstLag);
        out.put("any_target_reachable", targets.size() > unreachable.size());
        return Map.of("consumer_jmx", out);
    }

    /** Reads {@code records-lag-max} for every {@code client-id} on the target. */
    private static Map<String, @Nullable Long> readClientLag(MBeanServerConnection mbsc) {
        var out = new LinkedHashMap<String, @Nullable Long>();
        try {
            var pattern = new ObjectName(
                "kafka.consumer:type=consumer-fetch-manager-metrics,client-id=*");
            for (var name : mbsc.queryNames(pattern, null)) {
                var clientId = name.getKeyProperty("client-id");
                try {
                    var v = mbsc.getAttribute(name, "records-lag-max");
                    if (v instanceof Number n) {
                        out.put(clientId, n.longValue());
                    } else {
                        out.put(clientId, null);
                    }
                } catch (Exception e) {
                    out.put(clientId, null);
                }
            }
        } catch (Exception e) {
            // ignore — empty map signals no lag mbeans
        }
        return out;
    }
}
