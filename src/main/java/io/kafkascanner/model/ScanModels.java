package io.kafkascanner.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import java.util.List;
import java.util.Map;

/** All scan data models in one file to avoid cross-file import issues during initial build. */

public final class ScanModels {
    private ScanModels() {}

    // ── Policy ──────────────────────────────────────────────────
    @JsonPropertyOrder({"name", "version", "description", "controls", "scoring"})
    public record Policy(
        String name, String version, String description,
        List<Control> controls, Scoring scoring
    ) {}

    public record Control(
        String id, String title, Severity severity, Category category,
        String description, String condition, String message, String remediation,
        Compliance compliance,
        @JsonProperty("covered_by_flavor") List<String> coveredByFlavor
    ) {}

    public enum Severity { critical, high, medium, low, info }
    public enum Category { security, reliability, operational }

    public record Compliance(
        @JsonProperty("pci_dss") List<String> pciDss,
        List<String> soc2,
        List<String> iso27001
    ) {}

    public record Scoring(Map<String, Integer> weights, @JsonProperty("pass_threshold") int passThreshold) {}

    // ── Findings ─────────────────────────────────────────────────
    public record Finding(
        @JsonProperty("control_id") String controlId,
        Severity severity, Category category, String status,
        String title, String message, String remediation,
        Map<String, Object> evidence, Compliance compliance
    ) {}

    // ── Scan Result ──────────────────────────────────────────────
    public record ScanResult(
        @JsonProperty("cluster_name") String clusterName,
        String environment,
        @JsonProperty("scanned_at") String scannedAt,
        int score,
        @JsonProperty("pass_count") int passCount,
        @JsonProperty("fail_count") int failCount,
        @JsonProperty("na_count") int naCount,
        @JsonProperty("flavor_covered_count") int flavorCoveredCount,
        @JsonProperty("pass_rate") double passRate,
        List<Finding> findings,
        ClusterInfo cluster
    ) {}

    public record ClusterInfo(
        String name, int brokers, int topics,
        @JsonProperty("zk_nodes") int zkNodes,
        @JsonProperty("cluster_mode") String clusterMode,
        String flavor,
        @JsonProperty("flavor_source") String flavorSource
    ) {}
}
