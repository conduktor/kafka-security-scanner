package io.kafkascanner.collectors;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"unchecked", "NullAway"})
class CisCollectorTest {

    @Test
    void parsesCisCatTopLevelArray(@TempDir Path tmp) throws IOException {
        var report = tmp.resolve("ciscat.json");
        Files.writeString(report, """
            [
              {"id":"1.1","status":"Pass"},
              {"id":"1.2","status":"Pass"},
              {"id":"1.3","status":"Fail"},
              {"id":"1.4","result":"Pass"}
            ]
            """);
        var ctx = ctx(report.toString());
        var cis = (Map<?, ?>) new CisCollector().collect(ctx).get("cis");
        assertThat(cis.get("controls_total")).isEqualTo(4L);
        assertThat(cis.get("controls_passed")).isEqualTo(3L);
        assertThat((List<Object>) cis.get("controls_failed_ids")).containsExactly("1.3");
        assertThat((Double) cis.get("pass_ratio")).isEqualTo(0.75);
    }

    @Test
    void parsesKubeBenchTestsResults(@TempDir Path tmp) throws IOException {
        var report = tmp.resolve("kube-bench.json");
        Files.writeString(report, """
            {
              "Tests": [
                {"results": [
                  {"test_number":"1.1.1","status":"PASS"},
                  {"test_number":"1.1.2","status":"FAIL"}
                ]},
                {"results": [
                  {"test_number":"2.1.1","status":"PASS"}
                ]}
              ]
            }
            """);
        var ctx = ctx(report.toString());
        var cis = (Map<?, ?>) new CisCollector().collect(ctx).get("cis");
        assertThat(cis.get("controls_total")).isEqualTo(3L);
        assertThat(cis.get("controls_passed")).isEqualTo(2L);
        assertThat((List<Object>) cis.get("controls_failed_ids")).containsExactly("1.1.2");
    }

    @Test
    void parsesFlatControlsObject(@TempDir Path tmp) throws IOException {
        var report = tmp.resolve("flat.json");
        Files.writeString(report, """
            {"controls":[
              {"id":"A","status":"OK"},
              {"id":"B","status":"FAILED"}
            ]}
            """);
        var ctx = ctx(report.toString());
        var cis = (Map<?, ?>) new CisCollector().collect(ctx).get("cis");
        assertThat(cis.get("controls_total")).isEqualTo(2L);
        assertThat(cis.get("controls_passed")).isEqualTo(1L);
        assertThat((List<Object>) cis.get("controls_failed_ids")).containsExactly("B");
    }

    @Test
    void missingFileFlagsReportNotPresent(@TempDir Path tmp) {
        var ctx = ctx(tmp.resolve("nope.json").toString());
        var cis = (Map<?, ?>) new CisCollector().collect(ctx).get("cis");
        assertThat(cis.get("report_present")).isEqualTo(false);
        assertThat(cis.get("controls_total")).isEqualTo(0L);
    }

    private static CollectorContext ctx(String reportPath) {
        return new CollectorContext(
            "x:1", Duration.ofSeconds(5), null,
            null, null, null, null, null, null, null, null, null, null, null, null,
            null, null,
            reportPath,
            null, null, null,
            null, null,
            null, null, null, null,
            null, null, null,
            null, null,
            Map.of(), "vanilla", false);
    }
}
