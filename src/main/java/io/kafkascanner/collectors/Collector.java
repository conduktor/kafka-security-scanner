package io.kafkascanner.collectors;

import java.util.Map;

/**
 * Pluggable data source for the scanner. Each collector populates a slice of the
 * activation map that CEL conditions evaluate against.
 *
 * <p>Controls declare {@code requires: [collector-names]} in YAML. If a required
 * collector is unavailable in this run, the control resolves to {@code na} with a
 * rationale instead of silently passing.
 */
public interface Collector {

    /** Stable name used in `requires:` lists. Must be lowercase and hyphenated. */
    String name();

    /** True if this collector can run in the current environment / context. */
    boolean isAvailable(CollectorContext context);

    /**
     * Run the collector. The returned map is merged into the global scan data
     * under the collector's namespace key. Should never throw — return an empty
     * or partial map and surface errors via the context's logger.
     */
    Map<String, Object> collect(CollectorContext context);
}
