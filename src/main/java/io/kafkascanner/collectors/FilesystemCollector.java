package io.kafkascanner.collectors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
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

        var files = new HashMap<String, Map<String, Object>>();
        try (Stream<Path> entries = Files.list(dir)) {
            entries.forEach(p -> {
                if (Files.isRegularFile(p)) {
                    files.put(p.getFileName().toString(), inspect(p));
                }
            });
        } catch (IOException e) {
            System.err.println("[filesystem] list " + dir + " failed: " + e.getMessage());
        }
        fs.put("files", files);

        // Pre-computed booleans the CEL conditions can branch on.
        fs.put("jaas_present", files.containsKey("kafka_server_jaas.conf"));
        fs.put("server_properties_world_readable",
            isWorldReadable(files.get("server.properties")));
        fs.put("jaas_world_readable",
            isWorldReadable(files.get("kafka_server_jaas.conf")));
        fs.put("any_keystore_world_readable",
            files.entrySet().stream()
                .filter(e -> e.getKey().endsWith(".jks") || e.getKey().endsWith(".p12"))
                .anyMatch(e -> isWorldReadable(e.getValue())));

        return Map.of("fs", fs);
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
