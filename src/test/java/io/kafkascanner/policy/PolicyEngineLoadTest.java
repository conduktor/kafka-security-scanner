package io.kafkascanner.policy;

import static org.assertj.core.api.Assertions.assertThat;

import io.kafkascanner.model.ScanModels.Status;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Regression guard: every shipped policy file must load AND every control
 * must declare a real condition or covered_by_kafka_flavor (the engine's
 * {@link PolicyEngine#load(File)} validation should refuse anything else).
 */
class PolicyEngineLoadTest {

    @Test
    void enterpriseDefaultLoadsCleanly() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        assertThat(engine.policy().controls()).isNotEmpty();
        // Sanity: 100+ controls expected after passes 6-11.
        assertThat(engine.policy().controls().size()).isGreaterThan(100);
    }

    @Test
    void everyControlDeclaresAConditionOrFlavorCoverage() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        for (var c : engine.policy().controls()) {
            var hasRealCondition = c.condition() != null
                && !c.condition().isBlank()
                && !"true".equals(c.condition().trim());
            var coveredByFlavor = c.coveredByKafkaFlavor() != null
                && !c.coveredByKafkaFlavor().isEmpty();
            assertThat(hasRealCondition || coveredByFlavor)
                .as("control %s must have a real condition or covered_by_kafka_flavor",
                    c.id())
                .isTrue();
        }
    }

    @Test
    void controlIdsAreUnique() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        var ids = new HashSet<String>();
        for (var c : engine.policy().controls()) {
            assertThat(ids.add(c.id()))
                .as("duplicate control id: %s", c.id())
                .isTrue();
        }
    }

    @Test
    void evaluateAgainstEmptyDataReturnsAllNaOrCoveredOrFailed() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        var result = engine.evaluate(Map.of(), "empty", "vanilla", "test", java.util.Set.of());
        // Every control resolves to one of the legal statuses; evaluation must
        // never throw and must produce a deterministic count.
        var total = result.passCount() + result.failCount() + result.naCount()
            + result.errorCount();
        assertThat(total).isEqualTo(engine.policy().controls().size());
    }

    @Test
    void adminClientControlsAreNaWhenAdminClientDidNotRun() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        var result = engine.evaluate(Map.of(), "empty", "vanilla", "test", java.util.Set.of());

        assertThat(result.findings())
            .filteredOn(f -> "KAFKA-AUTH-001".equals(f.controlId()))
            .singleElement()
            .extracting("status")
            .isEqualTo(Status.na);
        assertThat(result.collectorsUnavailable()).contains("adminclient");
    }

    @Test
    void controlsUsingMissingAdminClientSlicesAreNa() throws Exception {
        var engine = PolicyEngine.load(new File("policies/enterprise-default.yaml"));
        var result = engine.evaluate(Map.of(
            "broker", java.util.List.of(Map.of("config", Map.of())),
            "kraft", Map.of("mode", "kraft"),
            "acl_metadata", Map.of("collected", false)
        ), "partial", "vanilla", "test", java.util.Set.of("adminclient"));

        assertThat(result.findings())
            .filteredOn(f -> "KAFKA-ACL-001".equals(f.controlId()))
            .singleElement()
            .extracting("status")
            .isEqualTo(Status.na);
        assertThat(result.collectorsUnavailable()).contains("adminclient:acl");
    }

    @Test
    void scanResultReportsCollectedClusterMode() throws Exception {
        var engine = PolicyEngine.load(new File("policies/test-minimal-valid.yaml"));
        var result = engine.evaluate(Map.of(
            "broker", java.util.List.of(Map.of()),
            "kraft", Map.of("mode", "zookeeper")
        ), "zk-cluster", "vanilla", "test", java.util.Set.of("adminclient"));

        assertThat(result.cluster().clusterMode()).isEqualTo("zookeeper");
    }

    @Test
    void customPolicyScoringWeightsAreApplied(@TempDir Path tmp) throws Exception {
        var policy = tmp.resolve("weighted.yaml");
        Files.writeString(policy, """
            name: weighted
            version: "1"
            controls:
              - id: TEST-001
                title: Weighted failure
                severity: high
                category: security
                condition: "false"
                message: failed
                remediation: fix
            scoring:
              weights:
                high: 25
              pass_threshold: 70
            """);

        var engine = PolicyEngine.load(policy.toFile());
        var result = engine.evaluate(Map.of(), "weighted", "vanilla", "test", java.util.Set.of());

        assertThat(result.score()).isEqualTo(75);
    }
}
