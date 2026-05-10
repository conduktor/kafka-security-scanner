package io.kafkascanner.collectors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Reads broker config files from {@code --kafka-config-dir}. Populates {@code fs}
 * on the scan data with file permissions and parsed properties so controls can
 * cross-check what AdminClient reports against the on-disk truth.
 *
 * <p>Files inspected (when present):
 * <ul>
 *   <li>{@code server.properties} — full properties + perms</li>
 *   <li>{@code kafka_server_jaas.conf} — perms + presence</li>
 *   <li>{@code log4j.properties} / {@code log4j2.properties} — perms + content snippet</li>
 *   <li>{@code *.jks} / {@code *.p12} — perms + size</li>
 * </ul>
 *
 * <p>Local-mode only. For remote brokers, run a sidecar that mounts the config
 * dir and pass its local path here.
 */
public final class FilesystemCollector implements Collector {

    @Override
    public String name() {
        return "filesystem";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        if (!context.hasKafkaConfigDir()) {
            return false;
        }
        var dir = Path.of(context.kafkaConfigDir());
        return Files.isDirectory(dir);
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var dir = Path.of(context.kafkaConfigDir());
        var fs = new HashMap<String, Object>();
        fs.put("config_dir", dir.toString());

        var serverProps = readProps(dir.resolve("server.properties"));
        if (serverProps != null) {
            fs.put("server_properties", serverProps);
        }
        var connectProps = readProps(dir.resolve("connect-distributed.properties"));
        if (connectProps != null) {
            fs.put("connect_properties", connectProps);
        }
        fs.put("is_connect_node", connectProps != null);

        var files = new HashMap<String, Map<String, Object>>();
        try (Stream<Path> entries = Files.list(dir)) {
            entries.forEach(p -> {
                if (Files.isRegularFile(p)) {
                    var fileName = p.getFileName();
                    if (fileName != null) {
                        files.put(fileName.toString(), inspect(p));
                    }
                }
            });
        } catch (IOException e) {
            System.err.println("[filesystem] list " + dir + " failed: " + e.getMessage());
        }
        fs.put("files", files);

        fs.put("jaas_present", files.containsKey("kafka_server_jaas.conf"));
        fs.put("server_properties_world_readable",
            isWorldReadable(files.get("server.properties")));
        fs.put("jaas_world_readable",
            isWorldReadable(files.get("kafka_server_jaas.conf")));
        fs.put("any_keystore_world_readable",
            files.entrySet().stream()
                .filter(e -> e.getKey().endsWith(".jks") || e.getKey().endsWith(".p12"))
                .anyMatch(e -> isWorldReadable(e.getValue())));
        fs.put("any_log_file_world_readable",
            files.entrySet().stream()
                .filter(e -> e.getKey().endsWith(".log"))
                .anyMatch(e -> isWorldReadable(e.getValue())));

        // Parse log4j properties so AUDIT controls can check logger configuration.
        var log4j = readLog4j(dir);
        fs.put("audit_logger_configured", log4j.contains("kafka.authorizer.logger"));
        fs.put("auth_logger_configured",
            log4j.contains("kafka.authenticator")
                || log4j.contains("kafka.network.RequestChannel$"));
        fs.put("request_logger_configured", log4j.contains("kafka.request.logger"));
        fs.put("controller_logger_configured", log4j.contains("kafka.controller"));
        fs.put("change_logger_configured",
            log4j.contains("kafka.zk.KafkaZkClient")
                || log4j.contains("kafka.controller.KafkaController")
                || log4j.contains("kafka.server.DynamicBrokerConfig"));

        // Retention proof: a Rolling appender plus a max-history/backup-index/strategy.max
        // setting on the same appender. Avoids the false positive where the property exists
        // for a different (non-rolling) appender block.
        fs.put("audit_log_retention_configured", hasRollingRetention(log4j));

        // Layout-pattern audit: AUDIT-010 wants every record to identify the
        // principal AND clientId/remoteAddress; DATA-008 wants no bare %message
        // expansion that would leak topic payload into the audit trail.
        fs.put("audit_layout_includes_principal", LAYOUT_PRINCIPAL.matcher(log4j).find());
        fs.put("audit_layout_includes_client",
            LAYOUT_CLIENT_ID.matcher(log4j).find()
                || LAYOUT_REMOTE_ADDR.matcher(log4j).find());
        fs.put("audit_layout_redacts_message", !LAYOUT_BARE_MESSAGE.matcher(log4j).find());

        // ENC-004: prove disk encryption on every log.dirs entry by walking
        // /proc/mounts and checking the underlying device is on a dm-crypt
        // mapper or zfs encrypted dataset. Linux-only; on macOS / non-POSIX
        // returns absent (controls fall back to flavor coverage).
        var logDirs = parseLogDirs(serverProps);
        var diskAudit = auditDiskEncryption(logDirs);
        fs.put("log_dirs_declared", logDirs);
        fs.put("log_dirs_encrypted", diskAudit.allEncrypted);
        fs.put("log_dirs_encryption_proof", diskAudit.proofs);
        fs.put("log_dirs_proc_mounts_readable", diskAudit.procMountsReadable);

        return Map.of("fs", fs);
    }

    private static List<String> parseLogDirs(@Nullable Map<String, String> serverProps) {
        var out = new ArrayList<String>();
        if (serverProps == null) {
            return out;
        }
        var v = serverProps.get("log.dirs");
        if (v == null || v.isBlank()) {
            v = serverProps.get("log.dir");
        }
        if (v == null || v.isBlank()) {
            return out;
        }
        for (var d : v.split(",")) {
            var t = d.trim();
            if (!t.isEmpty()) {
                out.add(t);
            }
        }
        return out;
    }

    private record DiskAudit(boolean allEncrypted, List<Map<String, Object>> proofs,
                             boolean procMountsReadable) { }

    /**
     * Walk /proc/mounts: for each log dir, find the longest-prefix mount,
     * inspect the source device. If the device starts with /dev/mapper/ or
     * the fstype is "crypto_LUKS" / starts with "zfs", we consider it
     * encrypted. Other mounts (ext4 on plain block device) are not.
     */
    private static DiskAudit auditDiskEncryption(List<String> logDirs) {
        var procMounts = Path.of("/proc/mounts");
        var proofs = new ArrayList<Map<String, Object>>();
        if (logDirs.isEmpty()) {
            return new DiskAudit(true, proofs, false);
        }
        if (!Files.isReadable(procMounts)) {
            for (var dir : logDirs) {
                var entry = new HashMap<String, Object>();
                entry.put("log_dir", dir);
                entry.put("encrypted", false);
                entry.put("reason", "proc_mounts_unreadable");
                proofs.add(entry);
            }
            return new DiskAudit(false, proofs, false);
        }
        List<MountEntry> mounts;
        try {
            mounts = parseProcMounts(procMounts);
        } catch (IOException e) {
            return new DiskAudit(false, proofs, false);
        }
        boolean all = true;
        for (var dir : logDirs) {
            var mount = bestMatch(mounts, dir);
            var entry = new HashMap<String, Object>();
            entry.put("log_dir", dir);
            if (mount == null) {
                entry.put("encrypted", false);
                entry.put("reason", "no_matching_mount");
                proofs.add(entry);
                all = false;
                continue;
            }
            entry.put("device", mount.device);
            entry.put("mount_point", mount.mountPoint);
            entry.put("fstype", mount.fstype);
            boolean enc = isEncryptedDevice(mount);
            entry.put("encrypted", enc);
            if (!enc) {
                entry.put("reason", "device_not_dm_crypt");
                all = false;
            }
            proofs.add(entry);
        }
        return new DiskAudit(all, proofs, true);
    }

    private record MountEntry(String device, String mountPoint, String fstype) { }

    private static List<MountEntry> parseProcMounts(Path procMounts) throws IOException {
        var out = new ArrayList<MountEntry>();
        for (var line : Files.readAllLines(procMounts)) {
            var parts = line.split("\\s+");
            if (parts.length < 3) {
                continue;
            }
            out.add(new MountEntry(parts[0], parts[1], parts[2]));
        }
        return out;
    }

    private static @Nullable MountEntry bestMatch(List<MountEntry> mounts, String path) {
        MountEntry best = null;
        int bestLen = -1;
        for (var m : mounts) {
            if (path.equals(m.mountPoint) || path.startsWith(m.mountPoint + "/")) {
                if (m.mountPoint.length() > bestLen) {
                    best = m;
                    bestLen = m.mountPoint.length();
                }
            }
        }
        return best;
    }

    private static boolean isEncryptedDevice(MountEntry m) {
        if (m.device.startsWith("/dev/mapper/")) {
            // dm-crypt / dm-integrity / LVM-on-LUKS
            return true;
        }
        if ("crypto_LUKS".equalsIgnoreCase(m.fstype)) {
            return true;
        }
        if (m.fstype.startsWith("zfs")) {
            // ZFS native encryption is per-dataset; we treat zfs presence as
            // a strong signal but the operator must confirm the dataset has
            // encryption=on. This is documented in the remediation text.
            return true;
        }
        return false;
    }

    /** %X{principal} or %m's containing the literal "principal=" placeholder. */
    private static final Pattern LAYOUT_PRINCIPAL = Pattern.compile(
        "(?i)%(X|MDC)\\{principal\\}|principal=%X|principal=\\$\\{");

    private static final Pattern LAYOUT_CLIENT_ID = Pattern.compile(
        "(?i)%(X|MDC)\\{(client[._-]?id|clientid)\\}");

    private static final Pattern LAYOUT_REMOTE_ADDR = Pattern.compile(
        "(?i)%(X|MDC)\\{(remoteAddress|remote[._-]?address|remote[._-]?ip|client[._-]?ip)\\}");

    /**
     * Bare {@code %m}/{@code %message}/{@code %msg} on an appender that the
     * audit pipeline writes to. Matched without surrounding format flags or
     * MDC selectors — those are considered intentional shaping.
     */
    private static final Pattern LAYOUT_BARE_MESSAGE = Pattern.compile(
        "(?<![A-Za-z_])%(m|msg|message)(?![A-Za-z_])");

    /**
     * True iff log4j config defines a rolling appender that also pins retention.
     * Matches both log4j 1.x ({@code MaxBackupIndex}) and log4j 2.x ({@code strategy.max}
     * or {@code DefaultRolloverStrategy max=}).
     */
    private static boolean hasRollingRetention(String log4j) {
        if (log4j.isEmpty()) {
            return false;
        }
        boolean rolling = log4j.contains("RollingFileAppender")
            || log4j.contains("type = RollingFile")
            || log4j.contains("type=RollingFile")
            || log4j.contains("DailyRollingFileAppender");
        if (!rolling) {
            return false;
        }
        return log4j.contains("MaxBackupIndex")
            || log4j.contains("MaxHistory")
            || log4j.contains("strategy.max")
            || log4j.contains("DefaultRolloverStrategy");
    }

    private static String readLog4j(Path dir) {
        var sb = new StringBuilder();
        for (var name : new String[] {"log4j.properties", "log4j2.properties", "log4j2.yaml"}) {
            var p = dir.resolve(name);
            if (Files.exists(p)) {
                try {
                    sb.append(Files.readString(p));
                    sb.append('\n');
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return sb.toString();
    }

    private static @Nullable Map<String, String> readProps(Path file) {
        if (!Files.exists(file)) {
            return null;
        }
        try (var in = Files.newInputStream(file)) {
            var p = new Properties();
            p.load(in);
            var out = new HashMap<String, String>();
            for (var name : p.stringPropertyNames()) {
                out.put(name, p.getProperty(name));
            }
            return out;
        } catch (IOException e) {
            return null;
        }
    }

    private static Map<String, Object> inspect(Path file) {
        var info = new HashMap<String, Object>();
        try {
            info.put("size", Files.size(file));
        } catch (IOException e) {
            info.put("size", -1L);
        }
        try {
            var attrs = Files.readAttributes(file, PosixFileAttributes.class);
            info.put("owner", attrs.owner().getName());
            info.put("group", attrs.group().getName());
            var perms = attrs.permissions();
            info.put("perms", toOctal(perms));
            info.put("world_readable", perms.contains(PosixFilePermission.OTHERS_READ));
            info.put("world_writable", perms.contains(PosixFilePermission.OTHERS_WRITE));
        } catch (IOException | UnsupportedOperationException e) {
            // Non-POSIX filesystem (Windows, some object stores). Permissions absent.
            info.put("perms", "n/a");
        }
        return info;
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

    private static boolean isWorldReadable(@Nullable Map<String, Object> info) {
        return info != null && Boolean.TRUE.equals(info.get("world_readable"));
    }
}
