package io.kafkascanner.collectors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Inspects a local Kafka broker JVM process. Reads {@code /proc/<pid>/cmdline},
 * {@code /proc/<pid>/limits}, {@code /proc/<pid>/status}. Surfaces JVM flags,
 * Kafka version (from the classpath jar), heap/GC settings, ulimits.
 *
 * <p>Local-mode only. Set {@code --kafka-pid} or rely on auto-detection from
 * {@code ps} output. On managed services this collector is unavailable.
 */
public final class ProcessCollector implements Collector {

    private static final Pattern KAFKA_JAR = Pattern.compile("kafka[_-][0-9.]+\\.jar");
    private static final Pattern HEAP_FLAG = Pattern.compile("-X(mx|ms)([0-9]+[gmkGMK]?)");
    private static final Pattern GC_FLAG = Pattern.compile("-XX:\\+Use(\\w+GC)");

    @Override
    public String name() {
        return "process";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        // Only Linux exposes /proc reliably.
        return Files.isDirectory(Path.of("/proc")) && findKafkaPid().isPresent();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var pid = findKafkaPid();
        if (pid.isEmpty()) {
            return Map.of();
        }
        var procDir = Path.of("/proc/" + pid.get());
        var process = new HashMap<String, Object>();
        process.put("pid", pid.get());

        var cmdline = readNullSeparated(procDir.resolve("cmdline"));
        process.put("cmdline", cmdline);
        process.put("jvm_flags", extractJvmFlags(cmdline));

        var heap = parseHeapFlags(cmdline);
        process.put("heap_min", heap.getOrDefault("ms", "default"));
        process.put("heap_max", heap.getOrDefault("mx", "default"));

        process.put("gc_algorithm", parseGcFlag(cmdline));
        var version = parseKafkaVersion(cmdline);
        if (version != null) {
            process.put("kafka_version", version);
            process.put("kafka_version_major", parseMajor(version));
            process.put("kafka_version_minor", parseMinor(version));
        }

        process.putAll(parseLimits(procDir.resolve("limits")));
        process.putAll(parseStatus(procDir.resolve("status")));

        return Map.of("process", process);
    }

    /** Parse /proc/<pid>/status to extract Uid/Gid (real,effective,saved,fs). */
    private static Map<String, Object> parseStatus(Path statusFile) {
        var out = new HashMap<String, Object>();
        if (!Files.exists(statusFile)) {
            return out;
        }
        try (Stream<String> lines = Files.lines(statusFile)) {
            lines.forEach(line -> {
                var lower = line.toLowerCase(java.util.Locale.ROOT);
                if (lower.startsWith("uid:")) {
                    var parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        try {
                            out.put("uid", Long.parseLong(parts[1]));
                            out.put("running_as_root", "0".equals(parts[1]));
                        } catch (NumberFormatException ignore) {
                            out.put("uid", -1L);
                            out.put("running_as_root", false);
                        }
                    }
                } else if (lower.startsWith("gid:")) {
                    var parts = line.trim().split("\\s+");
                    if (parts.length >= 2) {
                        try {
                            out.put("gid", Long.parseLong(parts[1]));
                        } catch (NumberFormatException ignore) {
                            out.put("gid", -1L);
                        }
                    }
                }
            });
        } catch (IOException e) {
            out.put("status_error", e.getMessage());
        }
        return out;
    }

    private static java.util.Optional<Long> findKafkaPid() {
        try (var procs = Files.list(Path.of("/proc"))) {
            return procs
                .filter(p -> p.getFileName().toString().chars().allMatch(Character::isDigit))
                .filter(ProcessCollector::isKafkaProcess)
                .map(p -> Long.parseLong(p.getFileName().toString()))
                .findFirst();
        } catch (IOException e) {
            return java.util.Optional.empty();
        }
    }

    private static boolean isKafkaProcess(Path procDir) {
        try {
            var cmdline = readNullSeparated(procDir.resolve("cmdline"));
            return cmdline.contains("kafka.Kafka") || cmdline.contains("KafkaServer");
        } catch (Exception e) {
            return false;
        }
    }

    private static java.util.List<String> extractJvmFlags(String cmdline) {
        var flags = new ArrayList<String>();
        for (var token : cmdline.split(" ")) {
            if (token.startsWith("-X") || token.startsWith("-D") || token.startsWith("--add")) {
                flags.add(token);
            }
        }
        return flags;
    }

    private static Map<String, String> parseHeapFlags(String cmdline) {
        var matcher = HEAP_FLAG.matcher(cmdline);
        var out = new HashMap<String, String>();
        while (matcher.find()) {
            out.put(matcher.group(1), matcher.group(2));
        }
        return out;
    }

    private static String parseGcFlag(String cmdline) {
        var matcher = GC_FLAG.matcher(cmdline);
        return matcher.find() ? matcher.group(1) : "unknown";
    }

    private static @Nullable String parseKafkaVersion(String cmdline) {
        var matcher = KAFKA_JAR.matcher(cmdline);
        if (matcher.find()) {
            var jar = matcher.group();
            var dash = jar.indexOf('-');
            if (dash > 0) {
                return jar.substring(dash + 1, jar.length() - ".jar".length());
            }
        }
        return null;
    }

    private static long parseMajor(String version) {
        var parts = version.split("\\.");
        if (parts.length >= 1) {
            try {
                return Long.parseLong(parts[0]);
            } catch (NumberFormatException ignore) {
                // fall through
            }
        }
        return -1L;
    }

    private static long parseMinor(String version) {
        var parts = version.split("\\.");
        if (parts.length >= 2) {
            try {
                return Long.parseLong(parts[1]);
            } catch (NumberFormatException ignore) {
                // fall through
            }
        }
        return -1L;
    }

    private static Map<String, Object> parseLimits(Path limitsFile) {
        var out = new HashMap<String, Object>();
        if (!Files.exists(limitsFile)) {
            return out;
        }
        try (Stream<String> lines = Files.lines(limitsFile)) {
            lines.skip(1).forEach(line -> {
                var lower = line.toLowerCase(java.util.Locale.ROOT);
                if (lower.contains("open files")) {
                    out.put("open_files_soft", extractLimit(line, 1));
                    out.put("open_files_hard", extractLimit(line, 2));
                } else if (lower.contains("processes")) {
                    out.put("processes_soft", extractLimit(line, 1));
                    out.put("processes_hard", extractLimit(line, 2));
                }
            });
        } catch (IOException e) {
            out.put("limits_error", e.getMessage());
        }
        return out;
    }

    private static long extractLimit(String line, int column) {
        var parts = line.trim().split("\\s+");
        if (parts.length < 4) {
            return -1L;
        }
        // Last 3 columns are: soft, hard, units. We want the column-th from end of numeric region.
        var raw = parts[parts.length - (4 - column)];
        if ("unlimited".equals(raw)) {
            return Long.MAX_VALUE;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    private static String readNullSeparated(Path file) {
        try {
            return Files.readString(file).replace('\0', ' ').trim();
        } catch (IOException e) {
            return "";
        }
    }
}
