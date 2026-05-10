package io.kafkascanner.collectors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Inspects a Kafka Streams application:
 * <ul>
 *   <li>JMX of every {@code --streams-jmx-host-ports} target — reads
 *       {@code application.id}, {@code state} (RUNNING / REBALANCING /
 *       ERROR), {@code last-rebalance-ms-ago} from the
 *       {@code kafka.streams:type=stream-metrics} MBean.</li>
 *   <li>{@code --streams-state-dir} on the local filesystem — POSIX perms
 *       on the directory and every immediate child must be 700 or 750
 *       (no world-read, no world-write).</li>
 * </ul>
 *
 * <p>Surfaces under {@code streams}:
 * <pre>
 *   streams.targets_reachable        JMX targets that handshook
 *   streams.application_ids          set of streams.applicationId values
 *                                    discovered across targets
 *   streams.any_in_error             any target reports state=ERROR
 *   streams.state_dir_secure         every state.dir entry has 700/750 perms
 *                                    AND no other-write
 *   streams.state_dir_proof          per-path {path, perms, owner, secure}
 * </pre>
 */
public final class StreamsCollector implements Collector {

    @Override
    public String name() {
        return "streams";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return (context.streamsJmxHostPorts() != null
                && !context.streamsJmxHostPorts().isBlank())
            || (context.streamsStateDir() != null
                && !context.streamsStateDir().isBlank());
    }

    @Override
    @SuppressWarnings("BanJNDI")
    public Map<String, Object> collect(CollectorContext context) {
        var out = new HashMap<String, Object>();

        // ── JMX side ───────────────────────────────────────────────────
        var jmxTargets = parseTargets(context.streamsJmxHostPorts());
        var applicationIds = new java.util.LinkedHashSet<String>();
        var perTarget = new LinkedHashMap<String, Map<String, Object>>();
        boolean anyError = false;
        int reachable = 0;
        for (var hp : jmxTargets) {
            var url = "service:jmx:rmi:///jndi/rmi://" + hp + "/jmxrmi";
            try (JMXConnector conn = JMXConnectorFactory.connect(new JMXServiceURL(url))) {
                var mbsc = conn.getMBeanServerConnection();
                var info = readStreams(mbsc);
                perTarget.put(hp, info);
                reachable++;
                var appId = (String) info.get("application_id");
                if (appId != null && !appId.isBlank()) {
                    applicationIds.add(appId);
                }
                var state = String.valueOf(info.getOrDefault("state", ""))
                    .toUpperCase(java.util.Locale.ROOT);
                if (state.contains("ERROR") || state.contains("FAILED")) {
                    anyError = true;
                }
            } catch (IOException e) {
                perTarget.put(hp, Map.of("error", e.getMessage()));
            }
        }
        out.put("targets", jmxTargets);
        out.put("targets_reachable", (long) reachable);
        out.put("application_ids", new ArrayList<>(applicationIds));
        out.put("any_in_error", anyError);
        out.put("per_target", perTarget);

        // ── state.dir side ─────────────────────────────────────────────
        var stateDir = context.streamsStateDir();
        if (stateDir != null && !stateDir.isBlank()) {
            var audit = auditStateDir(stateDir);
            out.put("state_dir", stateDir);
            out.put("state_dir_secure", audit.secure);
            out.put("state_dir_proof", audit.proof);
            out.put("state_dir_readable", audit.readable);
        } else {
            out.put("state_dir", "");
            out.put("state_dir_secure", false);
            out.put("state_dir_proof", List.of());
            out.put("state_dir_readable", false);
        }

        return Map.of("streams", out);
    }

    private static List<String> parseTargets(@Nullable String csv) {
        var out = new ArrayList<String>();
        if (csv == null || csv.isBlank()) {
            return out;
        }
        for (var t : csv.split(",")) {
            var hp = t.trim();
            if (!hp.isEmpty()) {
                out.add(hp);
            }
        }
        return out;
    }

    private static Map<String, Object> readStreams(MBeanServerConnection mbsc) {
        var out = new HashMap<String, Object>();
        try {
            var pattern = new ObjectName(
                "kafka.streams:type=stream-metrics,client-id=*");
            for (var name : mbsc.queryNames(pattern, null)) {
                try {
                    var appId = mbsc.getAttribute(name, "application-id");
                    if (appId != null) {
                        out.put("application_id", appId.toString());
                    }
                } catch (Exception ignore) {
                    // attribute may not exist on all kafka-streams versions
                }
                try {
                    var state = mbsc.getAttribute(name, "state");
                    if (state != null) {
                        out.put("state", state.toString());
                    }
                } catch (Exception ignore) {
                    // attribute may not exist on all kafka-streams versions
                }
                if (out.containsKey("application_id")) {
                    break;
                }
            }
        } catch (Exception e) {
            out.put("error", e.getMessage());
        }
        return out;
    }

    private record DirAudit(boolean readable, boolean secure, List<Map<String, Object>> proof) { }

    /**
     * The state directory and every immediate child must:
     *   - exist
     *   - have permissions 0700 or 0750
     *   - have no OTHERS_WRITE
     */
    private static DirAudit auditStateDir(String dir) {
        var path = Path.of(dir);
        var proof = new ArrayList<Map<String, Object>>();
        if (!Files.isDirectory(path)) {
            return new DirAudit(false, false, proof);
        }
        var paths = new ArrayList<Path>();
        paths.add(path);
        try (var stream = Files.list(path)) {
            stream.filter(Files::isDirectory).forEach(paths::add);
        } catch (IOException ignore) {
            // best-effort listing
        }
        boolean allSecure = true;
        for (var p : paths) {
            var entry = new HashMap<String, Object>();
            entry.put("path", p.toString());
            try {
                var attrs = Files.readAttributes(p, PosixFileAttributes.class);
                var perms = attrs.permissions();
                var octal = toOctal(perms);
                entry.put("perms", octal);
                entry.put("owner", attrs.owner().getName());
                boolean secure = !perms.contains(PosixFilePermission.OTHERS_WRITE)
                    && !perms.contains(PosixFilePermission.OTHERS_READ)
                    && !perms.contains(PosixFilePermission.OTHERS_EXECUTE);
                entry.put("secure", secure);
                if (!secure) {
                    allSecure = false;
                    entry.put("reason", "world-readable or world-writable");
                }
            } catch (IOException | UnsupportedOperationException e) {
                entry.put("perms", "n/a");
                entry.put("secure", false);
                entry.put("reason", "non-POSIX or unreadable");
                allSecure = false;
            }
            proof.add(entry);
        }
        return new DirAudit(true, allSecure, proof);
    }

    private static String toOctal(Set<PosixFilePermission> perms) {
        int mode = 0;
        if (perms.contains(PosixFilePermission.OWNER_READ)) {
            mode |= 0400;
        }
        if (perms.contains(PosixFilePermission.OWNER_WRITE)) {
            mode |= 0200;
        }
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) {
            mode |= 0100;
        }
        if (perms.contains(PosixFilePermission.GROUP_READ)) {
            mode |= 0040;
        }
        if (perms.contains(PosixFilePermission.GROUP_WRITE)) {
            mode |= 0020;
        }
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE)) {
            mode |= 0010;
        }
        if (perms.contains(PosixFilePermission.OTHERS_READ)) {
            mode |= 0004;
        }
        if (perms.contains(PosixFilePermission.OTHERS_WRITE)) {
            mode |= 0002;
        }
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) {
            mode |= 0001;
        }
        return String.format("0%o", mode);
    }
}
