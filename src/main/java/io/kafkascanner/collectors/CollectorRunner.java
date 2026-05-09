package io.kafkascanner.collectors;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Runs a list of collectors and records which ones succeeded. */
public final class CollectorRunner {

    public record Outcome(Map<String, Object> data, Set<String> ran, Set<String> skipped) { }

    private CollectorRunner() { }

    public static Outcome run(List<Collector> collectors, CollectorContext context) {
        var data = new HashMap<String, Object>();
        var ran = new LinkedHashSet<String>();
        var skipped = new LinkedHashSet<String>();

        for (var c : collectors) {
            if (!c.isAvailable(context)) {
                skipped.add(c.name());
                continue;
            }
            try {
                var out = c.collect(context);
                if (out != null) {
                    data.putAll(out);
                }
                ran.add(c.name());
            } catch (Exception e) {
                System.err.println("[" + c.name() + "] collector threw: " + e.getMessage());
                skipped.add(c.name());
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
