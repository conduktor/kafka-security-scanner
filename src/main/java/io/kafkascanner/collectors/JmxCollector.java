package io.kafkascanner.collectors;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

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
        var hostPort = context.jmxHostPort();
        if (hostPort == null) {
            return Map.of();
        }
        var url = "service:jmx:rmi:///jndi/rmi://" + hostPort + "/jmxrmi";
        var jmx = new HashMap<String, Object>();
        try (JMXConnector conn = JMXConnectorFactory.connect(new JMXServiceURL(url))) {
            var mbsc = conn.getMBeanServerConnection();
            jmx.put("under_replicated_partitions",
                readLong(mbsc, "kafka.server:type=ReplicaManager,name=UnderReplicatedPartitions"));
            jmx.put("offline_partitions_count",
                readLong(mbsc, "kafka.controller:type=KafkaController,name=OfflinePartitionsCount"));
            jmx.put("active_controller_count",
                readLong(mbsc, "kafka.controller:type=KafkaController,name=ActiveControllerCount"));
            jmx.put("request_handler_avg_idle_percent",
                readDouble(mbsc,
                    "kafka.server:type=KafkaRequestHandlerPool,name=RequestHandlerAvgIdlePercent"));
            jmx.put("network_processor_avg_idle_percent",
                readDouble(mbsc,
                    "kafka.network:type=SocketServer,name=NetworkProcessorAvgIdlePercent"));
            jmx.put("messages_in_per_sec",
                readDouble(mbsc, "kafka.server:type=BrokerTopicMetrics,name=MessagesInPerSec",
                    "OneMinuteRate"));
            jmx.put("bytes_in_per_sec",
                readDouble(mbsc, "kafka.server:type=BrokerTopicMetrics,name=BytesInPerSec",
                    "OneMinuteRate"));
            jmx.put("isr_shrinks_per_sec",
                readDouble(mbsc, "kafka.server:type=ReplicaManager,name=IsrShrinksPerSec",
                    "OneMinuteRate"));
            jmx.put("kafka_version", readString(mbsc,
                "kafka.server:type=app-info", "version"));
            jmx.put("jvm_heap_used_pct",
                readHeapPercent(mbsc));
            jmx.put("jvm_threads_count",
                readLong(mbsc, "java.lang:type=Threading", "ThreadCount"));
            jmx.put("os_load_avg",
                readDouble(mbsc, "java.lang:type=OperatingSystem", "SystemLoadAverage"));
            jmx.put("file_descriptor_used_pct",
                readFileDescriptorPercent(mbsc));
            return Map.of("jmx", jmx);
        } catch (IOException e) {
            System.err.println("[jmx] connect failed: " + e.getMessage());
            return Map.of();
        }
    }

    private static long readLong(MBeanServerConnection mbsc, String beanName) {
        return readLong(mbsc, beanName, "Value");
    }

    private static long readLong(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw instanceof Number n ? n.longValue() : -1L;
        } catch (Exception e) {
            return -1L;
        }
    }

    private static double readDouble(MBeanServerConnection mbsc, String beanName) {
        return readDouble(mbsc, beanName, "Value");
    }

    private static double readDouble(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw instanceof Number n ? n.doubleValue() : -1.0;
        } catch (Exception e) {
            return -1.0;
        }
    }

    private static String readString(MBeanServerConnection mbsc, String beanName, String attr) {
        try {
            var raw = mbsc.getAttribute(new ObjectName(beanName), attr);
            return raw == null ? "" : raw.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static double readHeapPercent(MBeanServerConnection mbsc) {
        try {
            var heap = mbsc.getAttribute(new ObjectName("java.lang:type=Memory"), "HeapMemoryUsage");
            if (heap instanceof javax.management.openmbean.CompositeData cd) {
                var used = ((Number) cd.get("used")).doubleValue();
                var max = ((Number) cd.get("max")).doubleValue();
                if (max > 0) {
                    return used / max * 100.0;
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return -1.0;
    }

    private static double readFileDescriptorPercent(MBeanServerConnection mbsc) {
        try {
            var os = new ObjectName("java.lang:type=OperatingSystem");
            var open = ((Number) mbsc.getAttribute(os, "OpenFileDescriptorCount")).doubleValue();
            var max = ((Number) mbsc.getAttribute(os, "MaxFileDescriptorCount")).doubleValue();
            if (max > 0) {
                return open / max * 100.0;
            }
        } catch (Exception e) {
            // fall through
        }
        return -1.0;
    }

    /** Useful for matching beans whose canonical name is case-sensitive. */
    @SuppressWarnings("unused")
    private static String normalize(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
