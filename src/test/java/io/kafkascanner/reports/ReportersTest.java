package io.kafkascanner.reports;

import static io.kafkascanner.model.ScanModels.Category.security;
import static io.kafkascanner.model.ScanModels.Severity.high;
import static io.kafkascanner.model.ScanModels.Status.fail;
import static org.assertj.core.api.Assertions.assertThat;

import io.kafkascanner.model.ScanModels.ClusterInfo;
import io.kafkascanner.model.ScanModels.Compliance;
import io.kafkascanner.model.ScanModels.Finding;
import io.kafkascanner.model.ScanModels.ScanResult;
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
            new ClusterInfo("cluster", 3, 12, 0, "kraft", "vanilla", "default"));
    }
}
