package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Ingests an external CIS benchmark report (cis-cat / kube-bench / lynis JSON
 * output) and surfaces it under {@code cis} so OPS-002 can demand a real
 * hardening artefact instead of a docs file.
 *
 * <p>Activated by {@code --cis-report=path/to/report.json}. Three accepted
 * shapes:
 * <ul>
 *   <li><b>cis-cat / inspec</b> — top-level array of controls each with
 *       {@code id} and {@code result} ("Pass"/"Fail").</li>
 *   <li><b>kube-bench</b> — root object with {@code Tests[*].results[*]}
 *       each carrying {@code test_number} and {@code status}.</li>
 *   <li><b>flat</b> — root object with {@code controls: [{id, status}]}.</li>
 * </ul>
 *
 * <p>Output:
 * <pre>
 *   cis.report_present       true
 *   cis.controls_total       127
 *   cis.controls_passed      116
 *   cis.controls_failed_ids  [...failures...]
 *   cis.pass_ratio           0.91
 * </pre>
 */
public final class CisCollector implements Collector {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String name() {
        return "cis";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.cisReportPath() != null && !context.cisReportPath().isBlank();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var pathStr = context.cisReportPath();
        if (pathStr == null || pathStr.isBlank()) {
            return Map.of();
        }
        var path = Path.of(pathStr);
        var out = new HashMap<String, Object>();
        out.put("report_path", path.toString());
        out.put("report_present", Files.isRegularFile(path));
        out.put("controls_total", 0L);
        out.put("controls_passed", 0L);
        out.put("controls_failed_ids", List.of());
        out.put("pass_ratio", 0.0);
        if (!Files.isRegularFile(path)) {
            out.put("error", "report not found");
            return Map.of("cis", out);
        }
        try {
            var root = JSON.readValue(Files.readAllBytes(path), Object.class);
            var counts = parse(root);
            out.put("controls_total", (long) counts.total);
            out.put("controls_passed", (long) counts.passed);
            out.put("controls_failed_ids", counts.failedIds);
            out.put("pass_ratio", counts.total == 0 ? 0.0
                : (double) counts.passed / counts.total);
        } catch (IOException e) {
            out.put("error", "parse failed: " + e.getMessage());
        }
        return Map.of("cis", out);
    }

    private record Counts(int total, int passed, List<String> failedIds) { }

    @SuppressWarnings("unchecked")
    private static Counts parse(Object root) {
        var failed = new ArrayList<String>();
        int total = 0;
        int passed = 0;
        if (root instanceof Map<?, ?> map) {
            // kube-bench: Tests[*].results[*]
            var tests = map.get("Tests");
            if (tests instanceof List<?> testList) {
                for (var t : testList) {
                    if (!(t instanceof Map<?, ?> tm)) {
                        continue;
                    }
                    var results = tm.get("results");
                    if (results instanceof List<?> rl) {
                        for (var r : rl) {
                            if (!(r instanceof Map<?, ?> rm)) {
                                continue;
                            }
                            total++;
                            var status = String.valueOf(rm.get("status") == null ? "" : rm.get("status"))
                                .toUpperCase(Locale.ROOT);
                            if (isPass(status)) {
                                passed++;
                            } else {
                                var idVal = rm.get("test_number");
                                if (idVal == null) {
                                    idVal = rm.get("id");
                                }
                                failed.add(idVal == null ? "?" : String.valueOf(idVal));
                            }
                        }
                    }
                }
            }
            // flat schema: { controls: [{id, status}, ...] }
            var controls = map.get("controls");
            if (controls instanceof List<?> cl) {
                for (var c : cl) {
                    if (!(c instanceof Map<?, ?> cm)) {
                        continue;
                    }
                    total++;
                    var status = pickStatus(cm);
                    if (isPass(status)) {
                        passed++;
                    } else {
                        var idVal = cm.get("id");
                        failed.add(idVal == null ? "?" : String.valueOf(idVal));
                    }
                }
            }
        } else if (root instanceof List<?> list) {
            // cis-cat / inspec top-level array
            for (var c : list) {
                if (!(c instanceof Map<?, ?> cm)) {
                    continue;
                }
                total++;
                var status = pickStatus(cm);
                if (isPass(status)) {
                    passed++;
                } else {
                    var idVal = cm.get("id");
                    if (idVal == null) {
                        idVal = cm.get("control_id");
                    }
                    failed.add(idVal == null ? "?" : String.valueOf(idVal));
                }
            }
        }
        return new Counts(total, passed, failed);
    }

    private static String pickStatus(Map<?, ?> cm) {
        for (var key : new String[] {"status", "result", "outcome"}) {
            var v = cm.get(key);
            if (v != null) {
                return String.valueOf(v).toUpperCase(Locale.ROOT);
            }
        }
        return "";
    }

    private static boolean isPass(String status) {
        return status.equals("PASS") || status.equals("PASSED")
            || status.equals("OK") || status.equals("SUCCESS");
    }
}
