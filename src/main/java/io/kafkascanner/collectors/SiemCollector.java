package io.kafkascanner.collectors;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Detects local SIEM/log-shipper presence — proves an audit pipeline by
 * pointing at a real process or an open shipper port, not a docs file.
 *
 * <p>Two parallel probes:
 * <ol>
 *   <li>{@link ProcessHandle#allProcesses()} command/cmdline against a known
 *       shipper-name set ({@code vector}, {@code fluentd}, {@code fluent-bit},
 *       {@code filebeat}, {@code auditbeat}, {@code splunkforwarder},
 *       {@code rsyslog}, {@code syslog-ng}, {@code logstash},
 *       {@code journalbeat}, {@code nxlog}).</li>
 *   <li>TCP-connect to the well-known ingest ports of those shippers on
 *       {@code 127.0.0.1}. A successful connect proves something is bound
 *       even if the cmdline is hidden.</li>
 * </ol>
 *
 * <p>Either signal sets {@code siem.detected = true}.
 */
public final class SiemCollector implements Collector {

    /** Shipper name → list of well-known ingest ports it commonly listens on. */
    private static final Map<String, int[]> KNOWN_SHIPPERS = Map.ofEntries(
        Map.entry("vector",          new int[] {8686, 9000, 9598}),
        Map.entry("fluentd",         new int[] {24224, 9880}),
        Map.entry("fluent-bit",      new int[] {2020, 24224}),
        Map.entry("filebeat",        new int[] {5066}),
        Map.entry("auditbeat",       new int[] {5067}),
        Map.entry("splunkforwarder", new int[] {8089, 9997}),
        Map.entry("rsyslog",         new int[] {514}),
        Map.entry("syslog-ng",       new int[] {601, 6514}),
        Map.entry("logstash",        new int[] {5044, 9600}),
        Map.entry("journalbeat",     new int[] {5066}),
        Map.entry("nxlog",           new int[] {})
    );

    @Override
    public String name() {
        return "siem";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        // No external dependency — runs anywhere the scanner can list its own processes.
        return true;
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var processHits = scanProcesses();
        var portHits = scanPorts();

        var detectedNames = new java.util.LinkedHashSet<String>();
        detectedNames.addAll(processHits);
        for (var p : portHits) {
            detectedNames.add(p.shipper());
        }

        var out = new HashMap<String, Object>();
        out.put("detected", !detectedNames.isEmpty());
        out.put("shippers_detected", new ArrayList<>(detectedNames));
        out.put("processes_matched", processHits);
        out.put("ports_open", portHits.stream()
            .map(p -> Map.of("shipper", (Object) p.shipper(), "port", (Object) (long) p.port()))
            .toList());
        return Map.of("siem", out);
    }

    private record PortHit(String shipper, int port) { }

    private static List<String> scanProcesses() {
        var found = new java.util.LinkedHashSet<String>();
        try {
            ProcessHandle.allProcesses().forEach(ph -> {
                var info = ph.info();
                var hay = (info.command().orElse("") + " " + info.commandLine().orElse(""))
                    .toLowerCase(Locale.ROOT);
                for (var name : KNOWN_SHIPPERS.keySet()) {
                    if (hay.contains(name)) {
                        found.add(name);
                    }
                }
            });
        } catch (SecurityException e) {
            System.err.println("[siem] process listing denied: " + e.getMessage());
        }
        return new ArrayList<>(found);
    }

    private static List<PortHit> scanPorts() {
        var probedPorts = new java.util.HashSet<Integer>();
        var hits = new ArrayList<PortHit>();
        for (var entry : KNOWN_SHIPPERS.entrySet()) {
            for (int port : entry.getValue()) {
                if (!probedPorts.add(port)) {
                    continue;
                }
                if (isLocalPortOpen(port, 200)) {
                    hits.add(new PortHit(entry.getKey(), port));
                }
            }
        }
        return hits;
    }

    private static boolean isLocalPortOpen(int port, int timeoutMs) {
        try (var sock = new Socket()) {
            sock.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Test hook: expose the set of recognised shipper names. */
    static Set<String> knownShippers() {
        return KNOWN_SHIPPERS.keySet();
    }
}
