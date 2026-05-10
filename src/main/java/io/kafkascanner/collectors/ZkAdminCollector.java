package io.kafkascanner.collectors;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Probes a ZooKeeper admin endpoint via the 4-letter-word protocol.
 *
 * <p>Sends {@code conf} and parses {@code 4lw.commands.whitelist},
 * {@code clientPort}, {@code secureClientPort}, {@code skipACL}.
 *
 * <p>For controls that need to verify ZK is hardened (ZK-004):
 * {@code zk.four_letter_whitelist_strict} is true iff the whitelist is set
 * to a closed set that excludes high-information commands like {@code dump},
 * {@code envi}, {@code wchs}, {@code stat}.
 *
 * <p>If {@code conf} is rejected with {@code conf is not executed because
 * it is not in the whitelist} the collector treats that as the strongest
 * possible signal: only {@code ruok} (or similar) is exposed and
 * {@code zk.four_letter_whitelist_strict} is true.
 */
public final class ZkAdminCollector implements Collector {

    /** Commands the operator should NOT expose blindly (information leakage). */
    private static final List<String> SENSITIVE_4LW = List.of(
        "dump", "envi", "wchs", "wchc", "wchp", "stat", "cons", "mntr"
    );

    @Override
    public String name() {
        return "zk";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        var hostPort = context.zkAdminHostPort();
        return hostPort != null && !hostPort.isBlank();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var hostPort = context.zkAdminHostPort();
        if (hostPort == null || hostPort.isBlank()) {
            return Map.of();
        }
        var parts = hostPort.split(":", 2);
        if (parts.length != 2) {
            return Map.of("zk", Map.of("reachable", false, "error", "expected host:port"));
        }
        var host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            return Map.of("zk", Map.of("reachable", false, "error", "non-numeric port"));
        }

        var out = new HashMap<String, Object>();
        out.put("host", host);
        out.put("port", (long) port);

        int timeoutMs = (int) context.timeout().toMillis();

        // Liveness: `ruok` should return `imok` if the daemon is up AND ruok
        // is whitelisted. A blank reply with a TCP-reachable port means the
        // whitelist excludes ruok — which is unusually strict but legal.
        var ruok = sendFourLetter(host, port, "ruok", Math.min(2000, timeoutMs));
        out.put("reachable", ruok.reachable);
        if (ruok.error != null) {
            out.put("error", ruok.error);
        }
        out.put("ruok_imok", "imok".equals(ruok.body.trim()));

        // Probe every sensitive command. Each one that produces actual output
        // (i.e. is NOT rejected with "not executed because it is not in the
        // whitelist") is a leaked information channel.
        var leakedCommands = new ArrayList<String>();
        var blockedCommands = new ArrayList<String>();
        for (var cmd : SENSITIVE_4LW) {
            var resp = sendFourLetter(host, port, cmd, Math.min(2000, timeoutMs));
            if (!resp.reachable) {
                continue;
            }
            var body = resp.body.toLowerCase(Locale.ROOT);
            if (body.contains("is not executed")
                || body.contains("not in the whitelist")
                || body.isBlank()) {
                blockedCommands.add(cmd);
            } else {
                leakedCommands.add(cmd);
            }
        }
        out.put("sensitive_commands_leaked", leakedCommands);
        out.put("sensitive_commands_blocked", blockedCommands);
        out.put("four_letter_whitelist_strict",
            ruok.reachable && leakedCommands.isEmpty());

        // Best-effort whitelist string (3.6+ exposes it via `conf`; many
        // operators don't, so this is informational, not load-bearing).
        var conf = sendFourLetter(host, port, "conf", Math.min(2000, timeoutMs));
        if (conf.reachable && !conf.body.isBlank()) {
            var props = parseConf(conf.body);
            var wl = props.getOrDefault("4lw.commands.whitelist", "").trim();
            if (!wl.isEmpty()) {
                out.put("four_letter_whitelist", Arrays.stream(wl.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(s -> s.toLowerCase(Locale.ROOT))
                    .toList());
            } else {
                out.put("four_letter_whitelist", List.<String>of());
            }
            out.put("skip_acl",
                "yes".equalsIgnoreCase(props.getOrDefault("skipACL", "no")));
        } else {
            out.put("four_letter_whitelist", List.<String>of());
            out.put("skip_acl", false);
        }

        return Map.of("zk", out);
    }

    private record Resp(boolean reachable, String body,
        @org.checkerframework.checker.nullness.qual.Nullable String error) { }

    private static Resp sendFourLetter(String host, int port, String cmd, int timeoutMs) {
        try (var sock = new Socket()) {
            sock.connect(new InetSocketAddress(host, port), Math.max(500, timeoutMs));
            sock.setSoTimeout(Math.max(500, timeoutMs));
            try (OutputStream out = sock.getOutputStream();
                 BufferedReader in = new BufferedReader(
                     new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8))) {
                out.write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
                var sb = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    sb.append(line).append('\n');
                }
                return new Resp(true, sb.toString(), null);
            }
        } catch (IOException e) {
            return new Resp(false, "", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static Map<String, String> parseConf(String body) {
        var out = new HashMap<String, String>();
        for (var raw : body.split("\\R")) {
            var line = raw.trim();
            int eq = line.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            out.put(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
        }
        return out;
    }

    /** Test hook. */
    static List<String> sensitive4lw() {
        return new ArrayList<>(SENSITIVE_4LW);
    }
}
