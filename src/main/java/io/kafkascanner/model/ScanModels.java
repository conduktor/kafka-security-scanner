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
    ) {
        public Policy {
            controls = controls == null ? List.of() : List.copyOf(controls);
        }
    }

    public record Control(
        String id, String title, Severity severity, Category category,
        String description, String condition, String message, String remediation,
        Compliance compliance,
        @JsonProperty("covered_by_kafka_flavor") List<String> coveredByKafkaFlavor,
        List<String> requires,
        @JsonProperty("requires_per_mode") Map<String, List<String>> requiresPerMode
    ) {
        public Control {
            coveredByKafkaFlavor = coveredByKafkaFlavor == null
                ? List.of() : List.copyOf(coveredByKafkaFlavor);
            requires = requires == null ? List.of() : List.copyOf(requires);
            requiresPerMode = requiresPerMode == null ? Map.of() : Map.copyOf(requiresPerMode);
        }
    }

    public enum Severity { critical, high, medium, low, info }
    public enum Category { security, reliability, operational }
    public enum Status { pass, fail, na, covered_by_flavor, error }

    public record Compliance(
        @JsonProperty("pci_dss") List<String> pciDss,
        List<String> soc2,
        List<String> iso27001,
        List<String> nist,
        List<String> cwe
    ) {
        public Compliance(List<String> pciDss, List<String> soc2, List<String> iso27001) {
            this(pciDss, soc2, iso27001, List.of(), List.of());
        }

        public Compliance {
            pciDss = pciDss == null ? List.of() : List.copyOf(pciDss);
            soc2 = soc2 == null ? List.of() : List.copyOf(soc2);
            iso27001 = iso27001 == null ? List.of() : List.copyOf(iso27001);
            nist = nist == null ? List.of() : List.copyOf(nist);
            cwe = cwe == null ? List.of() : List.copyOf(cwe);
        }
    }

    public record Scoring(Map<String, Integer> weights, @JsonProperty("pass_threshold") int passThreshold) {
        public Scoring {
            weights = weights == null ? Map.of() : Map.copyOf(weights);
        }
    }

    // ── Findings ─────────────────────────────────────────────────
    public record Finding(
        @JsonProperty("control_id") String controlId,
        Severity severity, Category category, Status status,
        String title, String message, String remediation,
        Map<String, Object> evidence, Compliance compliance
    ) {
        public Finding {
            evidence = evidence == null ? Map.of() : Map.copyOf(evidence);
        }
    }

    // ── Scan Result ──────────────────────────────────────────────
    public record ScanResult(
        @JsonProperty("cluster_name") String clusterName,
        String environment,
        @JsonProperty("scanned_at") String scannedAt,
        int score,
        @JsonProperty("pass_count") int passCount,
        @JsonProperty("fail_count") int failCount,
        @JsonProperty("na_count") int naCount,
        @JsonProperty("kafka_flavor_covered_count") int kafkaFlavorCoveredCount,
        @JsonProperty("error_count") int errorCount,
        @JsonProperty("pass_rate") double passRate,
        @JsonProperty("collectors_used") List<String> collectorsUsed,
        @JsonProperty("collectors_unavailable") List<String> collectorsUnavailable,
        @JsonProperty("control_results") List<Finding> controlResults,
        List<Finding> findings,
        ClusterInfo cluster
    ) {
        public ScanResult {
            collectorsUsed = collectorsUsed == null ? List.of() : List.copyOf(collectorsUsed);
            collectorsUnavailable = collectorsUnavailable == null
                ? List.of() : List.copyOf(collectorsUnavailable);
            controlResults = controlResults == null ? List.of() : List.copyOf(controlResults);
            findings = findings == null ? List.of() : List.copyOf(findings);
        }
    }

    public record ClusterInfo(
        String name, int brokers, int topics,
        @JsonProperty("zk_nodes") int zkNodes,
        @JsonProperty("cluster_mode") String clusterMode,
        @JsonProperty("kafka_flavor") String kafkaFlavor,
        @JsonProperty("kafka_flavor_source") String kafkaFlavorSource
    ) {}
}
