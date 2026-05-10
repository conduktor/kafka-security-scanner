package io.kafkascanner.reports;

import static io.kafkascanner.model.ScanModels.Category.security;
import static io.kafkascanner.model.ScanModels.Severity.high;
import static io.kafkascanner.model.ScanModels.Status.fail;
import static org.assertj.core.api.Assertions.assertThat;

import io.kafkascanner.model.ScanModels.ClusterInfo;
import io.kafkascanner.model.ScanModels.Compliance;
import io.kafkascanner.model.ScanModels.Finding;
import io.kafkascanner.model.ScanModels.ScanResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.Loader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReportersTest {

    @Test
    void pdfFindingsPaginateAcrossMultiplePages(@TempDir Path tmp) throws Exception {
        var result = resultWithFindings(80);

        var written = Reporters.write(result, "pdf", tmp);

        assertThat(written).hasSize(1);
        try (var pdf = Loader.loadPDF(written.getFirst().toFile())) {
            assertThat(pdf.getNumberOfPages()).isGreaterThan(2);
        }
    }

    @Test
    void csvIncludesAllControlResultsEvidenceAndCompliance(@TempDir Path tmp) throws Exception {
        var result = resultWithControlResults();

        var written = Reporters.write(result, "csv", tmp);
        var csv = Files.readString(written.getFirst());

        assertThat(csv).contains("PASS-001");
        assertThat(csv).contains("FAIL-001");
        assertThat(csv).contains("nist");
        assertThat(csv).contains("AU-2");
        assertThat(csv).contains("reason");
    }

    private static ScanResult resultWithFindings(int count) {
        var findings = new ArrayList<Finding>();
        for (int i = 0; i < count; i++) {
            findings.add(new Finding(
                "SEC-" + String.format("%03d", i),
                high,
                security,
                fail,
                "Finding title " + i,
                "This is a finding message long enough to exercise repeated PDF rows.",
                "Fix it",
                Map.of(),
                new Compliance(List.of(), List.of(), List.of())));
        }
        return new ScanResult(
            "cluster",
            "test",
            "2026-05-10T00:00:00Z",
            50,
            0,
            count,
            0,
            0,
            0,
            0.0,
            List.of("adminclient"),
            List.of(),
            findings,
            findings,
            new ClusterInfo("cluster", 3, 12, 0, "kraft", "vanilla", "default"));
    }

    private static ScanResult resultWithControlResults() {
        var passFinding = new Finding(
            "PASS-001",
            high,
            security,
            io.kafkascanner.model.ScanModels.Status.pass,
            "Pass title",
            "passed",
            "none",
            Map.of("reason", "condition evaluated true"),
            new Compliance(List.of("10.2"), List.of(), List.of(), List.of("AU-2"), List.of("778")));
        var failFinding = new Finding(
            "FAIL-001",
            high,
            security,
            fail,
            "Fail title",
            "failed",
            "fix",
            Map.of("reason", "condition evaluated false"),
            new Compliance(List.of(), List.of(), List.of(), List.of(), List.of()));
        return new ScanResult(
            "cluster",
            "test",
            "2026-05-10T00:00:00Z",
            90,
            1,
            1,
            0,
            0,
            0,
            50.0,
            List.of("adminclient"),
            List.of(),
            List.of(passFinding, failFinding),
            List.of(failFinding),
            new ClusterInfo("cluster", 3, 12, 0, "kraft", "vanilla", "default"));
    }
}
