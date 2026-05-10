package io.kafkascanner.collectors;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Runs a list of collectors concurrently on virtual threads and records
 * which ones succeeded. Each collector lives in its own task so an HTTP
 * collector waiting on a slow Confluent Cloud endpoint doesn't block a
 * cheap filesystem scan.
 *
 * <p>Per-collector timeout: {@code context.timeout()} (the same budget the
 * collector applies to its own I/O). A collector that exceeds the budget
 * is treated as skipped — the scan still finishes deterministically.
 */
public final class CollectorRunner {

    public record Outcome(Map<String, Object> data, Set<String> ran, Set<String> skipped) { }

    private CollectorRunner() { }

    public static Outcome run(List<Collector> collectors, CollectorContext context) {
        var data = new LinkedHashMap<String, Object>();
        var ran = new LinkedHashSet<String>();
        var skipped = new LinkedHashSet<String>();

        // Two phases: filter by isAvailable on the calling thread (cheap, no I/O),
        // then dispatch the actual collect() calls concurrently on virtual threads.
        var live = new java.util.ArrayList<Collector>();
        for (var c : collectors) {
            if (!c.isAvailable(context)) {
                skipped.add(c.name());
                continue;
            }
            live.add(c);
        }

        // Per-collector deadline: each collector already passes its own timeout
        // to HTTP / JMX clients. Future.get() applies the same envelope from
        // the runner's perspective so a stuck collector can't pin the scan.
        long perCollectorMs = Math.max(1_000, context.timeout().toMillis() + 2_000);

        var pending = new LinkedHashMap<Collector, Future<Map<String, Object>>>();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (var c : live) {
                pending.put(c, executor.submit(() -> {
                    try {
                        var out = c.collect(context);
                        return out == null ? Map.<String, Object>of() : out;
                    } catch (Exception e) {
                        // Surface to stderr so the operator sees what failed,
                        // and propagate so Future.get throws ExecutionException.
                        System.err.println("[" + c.name() + "] collector threw: "
                            + e.getMessage());
                        throw e;
                    }
                }));
            }
            for (var entry : pending.entrySet()) {
                var c = entry.getKey();
                try {
                    var out = entry.getValue().get(perCollectorMs, TimeUnit.MILLISECONDS);
                    data.putAll(out);
                    ran.add(c.name());
                } catch (Exception e) {
                    if (e instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    System.err.println("[" + c.name() + "] timed out / failed: "
                        + e.getClass().getSimpleName());
                    entry.getValue().cancel(true);
                    skipped.add(c.name());
                }
            }
        }

        return new Outcome(data, Set.copyOf(ran), Set.copyOf(skipped));
    }

    /** Resolve collector names from a comma-separated user input, ignoring blanks. */
    public static Set<String> parseNames(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        var result = new HashSet<String>();
        for (var part : csv.split(",")) {
            var trimmed = part.trim().toLowerCase(java.util.Locale.ROOT);
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}
