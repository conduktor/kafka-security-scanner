package io.kafkascanner.policy;

import static io.kafkascanner.model.ScanModels.Status.covered_by_flavor;
import static io.kafkascanner.model.ScanModels.Status.fail;
import static io.kafkascanner.model.ScanModels.Status.pass;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"unchecked", "NullAway"})
class PolicyEngineAuditEvidenceTest {

    @Test
    void emitsPerControlResultsWithRedactedEvidenceAndCompliance(@TempDir Path tmp)
        throws Exception {
        var policy = tmp.resolve("audit.yaml");
        Files.writeString(policy, """
            name: audit
            version: "1"
            controls:
              - id: AUDIT-001
                title: Audit evidence exists
                severity: high
                category: security
                condition: "brokers.exists(b, 'config' in b && 'sasl.jaas.config' in b.config)"
                message: failed
                remediation: fix
                compliance:
                  pci_dss: ["10.2"]
                  nist: ["AU-2"]
                  cwe: ["778"]
            """);

        var engine = PolicyEngine.load(policy.toFile());
        var result = engine.evaluate(Map.of(
                "broker", List.of(Map.of("config", Map.of(
                    "sasl.jaas.config", "PlainLoginModule password=\"secret\";"))),
                "kraft", Map.of("mode", "kraft")
            ),
            "cluster", "vanilla", "test", Set.of("adminclient"));

        assertThat(result.findings()).isEmpty();
        assertThat(result.controlResults()).singleElement()
            .satisfies(control -> {
                assertThat(control.status()).isEqualTo(pass);
                assertThat(control.compliance().nist()).containsExactly("AU-2");
                assertThat(control.compliance().cwe()).containsExactly("778");
                var observed = (Map<String, Object>) control.evidence().get("observed");
                var brokers = (List<Map<String, Object>>) observed.get("brokers");
                var config = (Map<String, Object>) brokers.getFirst().get("config");
                assertThat(config.get("sasl.jaas.config")).isEqualTo("<redacted>");
            });
    }

    @Test
    void manualFlavorOverrideDoesNotAutomaticallyCoverControls(@TempDir Path tmp)
        throws Exception {
        var policy = tmp.resolve("coverage.yaml");
        Files.writeString(policy, """
            name: coverage
            version: "1"
            controls:
              - id: COVER-001
                title: Coverage must be verified
                severity: high
                category: security
                condition: "false"
                covered_by_kafka_flavor: [aws-msk]
                message: failed
                remediation: fix
            """);

        var engine = PolicyEngine.load(policy.toFile());
        var result = engine.evaluate(Map.of(), "cluster", "aws-msk", "override", Set.of());

        assertThat(result.controlResults()).singleElement()
            .satisfies(control -> {
                assertThat(control.status()).isEqualTo(fail);
                var coverage = (Map<String, Object>) control.evidence().get("flavor_coverage");
                assertThat(coverage.get("verified")).isEqualTo(false);
                assertThat(coverage.get("reason")).asString().contains("manual flavor override");
            });
    }

    @Test
    void managedServiceCoverageRequiresVendorCollectorEvidence(@TempDir Path tmp)
        throws Exception {
        var policy = tmp.resolve("coverage.yaml");
        Files.writeString(policy, """
            name: coverage
            version: "1"
            controls:
              - id: COVER-001
                title: Coverage must be verified
                severity: high
                category: security
                condition: "false"
                covered_by_kafka_flavor: [aws-msk]
                message: failed
                remediation: fix
            """);

        var engine = PolicyEngine.load(policy.toFile());
        var result = engine.evaluate(Map.of(
                "aws", Map.of("sdk_available", true, "cluster_arn", "arn:aws:kafka:us-east-1:1:cluster/x/1")
            ),
            "cluster", "aws-msk", "hostname:b-1.x.kafka.us-east-1.amazonaws.com", Set.of("awsmsk"));

        assertThat(result.controlResults()).singleElement()
            .satisfies(control -> {
                assertThat(control.status()).isEqualTo(covered_by_flavor);
                var coverage = (Map<String, Object>) control.evidence().get("flavor_coverage");
                assertThat(coverage.get("verified")).isEqualTo(true);
            });
    }
}
