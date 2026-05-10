package io.kafkascanner.collectors;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.management.JMException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Pulls broker MBeans over RMI. Populates the {@code jmx} key on the scan data
 * with reliability and load metrics referenced by REL/AVAIL/PERF controls.
 *
 * <p>Set {@code --jmx-host-port host:9999} to enable. The broker must be started
 * with {@code -Dcom.sun.management.jmxremote.port=9999} (or the standard Kafka
 * {@code KAFKA_JMX_OPTS}). One target per scan; controls then read
 * {@code cluster.jmx.<metric>}.
 */
public final class JmxCollector implements Collector {

    @Override
    public String name() {
        return "jmx";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasJmx();
    }

    @Override
    @SuppressWarnings("BanJNDI")  // JMX RMI is a legitimate JNDI use; broker host is operator-supplied.
    public Map<String, Object> collect(CollectorContext context) {
        var raw = context.jmxHostPort();
        if (raw == null || raw.isBlank()) {
            return Map.of();
        }
        // Comma-separated multi-target. Single value still works.
        var targets = new ArrayList<String>();
        for (var t : raw.split(",")) {
            var hp = t.trim();
            if (!hp.isEmpty()) {
                targets.add(hp);
            }
        }

        var aggregate = new HashMap<String, Object>();
        var perTarget = new LinkedHashMap<String, Map<String, Object>>();
        var unreachable = new ArrayList<String>();

        for (var hp : targets) {
            var single = collectFromOne(hp, context.timeout());
            if (single == null) {
                unreachable.add(hp);
                continue;
            }
            perTarget.put(hp, single);
        }

        // Aggregate: pessimistic. Cluster URP is max(URP) across brokers,
        // active_controller_count is max (must be 1 cluster-wide), etc.
        if (!perTarget.isEmpty()) {
            mergeMax(aggregate, perTarget, "under_replicated_partitions");
            mergeMax(aggregate, perTarget, "offline_partitions_count");
            mergeMax(aggregate, perTarget, "active_controller_count");
            mergeMin(aggregate, perTarget, "request_handler_avg_idle_percent");
            mergeMin(aggregate, perTarget, "network_processor_avg_idle_percent");
            mergeMax(aggregate, perTarget, "messages_in_per_sec");
            mergeMax(aggregate, perTarget, "bytes_in_per_sec");
            mergeMax(aggregate, perTarget, "isr_shrinks_per_sec");
            mergeMax(aggregate, perTarget, "jvm_heap_used_pct");
            mergeMax(aggregate, perTarget, "jvm_threads_count");
            mergeMax(aggregate, perTarget, "os_load_avg");
            mergeMax(aggregate, perTarget, "file_descriptor_used_pct");
            // kafka_version: report the first observed value
            for (var v : perTarget.values()) {
                if (v.get("kafka_version") instanceof String s) {
                    aggregate.put("kafka_version", s);
                    break;
                }
            }
        }
        aggregate.put("targets", targets);
        aggregate.put("targets_reachable", targets.size() - unreachable.size());
        aggregate.put("targets_unreachable", unreachable);
        aggregate.put("per_target", perTarget);
        return Map.of("jmx", aggregate);
    }

    @SuppressWarnings("BanJNDI")
    private static @Nullable Map<String, Object> collectFromOne(String hostPort, java.time.Duration timeout) {
        var url = "service:jmx:rmi:///jndi/rmi://" + hostPort + "/jmxrmi";
        var jmx = new HashMap<String, Object>();
        try (JMXConnector conn = JmxConnectorSupport.connect(url, timeout)) {
            var mbsc = conn.getMBeanServerConnection();
            putIfPresent(jmx, "under_replicated_partitions",
                readLong(mbsc, "kafka.server:type=ReplicaManager,name=UnderReplicatedPartitions"));
            putIfPresent(jmx, "offline_partitions_count",
                readLong(mbsc, "kafka.controller:type=KafkaController,name=OfflinePartitionsCount"));
            putIfPresent(jmx, "active_controller_count",
                readLong(mbsc, "kafka.controller:type=KafkaController,name=ActiveControllerCount"));
            putIfPresent(jmx, "request_handler_avg_idle_percent",
                readDouble(mbsc,
                    "kafka.server:type=KafkaRequestHandlerPool,name=RequestHandlerAvgIdlePercent"));
            putIfPresent(jmx, "network_processor_avg_idle_percent",
                readDouble(mbsc,
                    "kafka.network:type=SocketServer,name=NetworkProcessorAvgIdlePercent"));
            putIfPresent(jmx, "messages_in_per_sec",
                readDouble(mbsc, "kafka.server:type=BrokerTopicMetrics,name=MessagesInPerSec",
                    "OneMinuteRate"));
            putIfPresent(jmx, "bytes_in_per_sec",
                readDouble(mbsc, "kafka.server:type=BrokerTopicMetrics,name=BytesInPerSec",
                    "OneMinuteRate"));
            putIfPresent(jmx, "isr_shrinks_per_sec",
                readDouble(mbsc, "kafka.server:type=ReplicaManager,name=IsrShrinksPerSec",
                    "OneMinuteRate"));
            putIfPresent(jmx, "kafka_version", readString(mbsc,
                "kafka.server:type=app-info", "version"));
            putIfPresent(jmx, "jvm_heap_used_pct", readHeapPercent(mbsc));
            putIfPresent(jmx, "jvm_threads_count",
                readLong(mbsc, "java.lang:type=Threading", "ThreadCount"));
            putIfPresent(jmx, "os_load_avg",
                readDouble(mbsc, "java.lang:type=OperatingSystem", "SystemLoadAverage"));
            putIfPresent(jmx, "file_descriptor_used_pct", readFileDescriptorPercent(mbsc));
            return jmx;
        } catch (IOException e) {
            System.err.println("[jmx] connect failed for " + hostPort + ": " + e.getMessage());
            return null;
        }
    }

    private static void mergeMax(Map<String, Object> aggregate,
        Map<String, Map<String, Object>> perTarget, String key) {
        Double bestD = null;
        Long bestL = null;
        for (var v : perTarget.values()) {
            var raw = v.get(key);
            if (raw instanceof Long l) {
                bestL = bestL == null ? l : Math.max(bestL, l);
            } else if (raw instanceof Double d) {
                bestD = bestD == null ? d : Math.max(bestD, d);
            }
        }
        if (bestL != null) {
            aggregate.put(key, bestL);
        } else if (bestD != null) {
            aggregate.put(key, bestD);
        }
    }

    private static void mergeMin(Map<String, Object> aggregate,
        Map<String, Map<String, Object>> perTarget, String key) {
        Double bestD = null;
        Long bestL = null;
        for (var v : perTarget.values()) {
            var raw = v.get(key);
            if (raw instanceof Long l) {
                bestL = bestL == null ? l : Math.min(bestL, l);
            } else if (raw instanceof Double d) {
                bestD = bestD == null ? d : Math.min(bestD, d);
            }
        }
        if (bestL != null) {
            aggregate.put(key, bestL);
        } else if (bestD != null) {
            aggregate.put(key, bestD);
        }
    }

    private static @Nullable Long readLong(MBeanServerConnection mbsc, String beanName) {
        return readLong(mbsc, beanName, "Value");
    }

    private static @Nullable Long readLong(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw instanceof Number n ? n.longValue() : null;
        } catch (JMException | IOException e) {
            return null;
        }
    }

    private static @Nullable Double readDouble(MBeanServerConnection mbsc, String beanName) {
        return readDouble(mbsc, beanName, "Value");
    }

    private static @Nullable Double readDouble(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw instanceof Number n ? n.doubleValue() : null;
        } catch (JMException | IOException e) {
            return null;
        }
    }

    private static @Nullable String readString(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw == null ? null : raw.toString();
        } catch (JMException | IOException e) {
            return null;
        }
    }

    private static @Nullable Double readHeapPercent(MBeanServerConnection mbsc) {
        try {
            var heap = mbsc.getAttribute(new ObjectName("java.lang:type=Memory"), "HeapMemoryUsage");
            if (heap instanceof javax.management.openmbean.CompositeData cd) {
                var used = ((Number) cd.get("used")).doubleValue();
                var max = ((Number) cd.get("max")).doubleValue();
                if (max > 0) {
                    return used / max * 100.0;
                }
            }
        } catch (JMException | IOException | ClassCastException e) {
            // fall through
        }
        return null;
    }

    private static @Nullable Double readFileDescriptorPercent(MBeanServerConnection mbsc) {
        try {
            var os = new ObjectName("java.lang:type=OperatingSystem");
            var open = ((Number) mbsc.getAttribute(os, "OpenFileDescriptorCount")).doubleValue();
            var max = ((Number) mbsc.getAttribute(os, "MaxFileDescriptorCount")).doubleValue();
            if (max > 0) {
                return open / max * 100.0;
            }
        } catch (JMException | IOException | ClassCastException e) {
            // fall through
        }
        return null;
    }

    private static void putIfPresent(Map<String, Object> jmx, String key, @Nullable Object value) {
        if (value != null) {
            jmx.put(key, value);
        }
    }
}
