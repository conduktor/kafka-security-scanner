package io.kafkascanner.reports;

import static io.kafkascanner.model.ScanModels.Finding;
import static io.kafkascanner.model.ScanModels.ScanResult;
import static io.kafkascanner.model.ScanModels.Severity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.checkerframework.checker.nullness.qual.Nullable;

/** Multi-format report writers (JSON, SARIF, HTML, CSV, PDF). */
public final class Reporters {

    private static final ObjectMapper JSON = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT);

    private static final Set<String> KNOWN_FORMATS = Set.of(
        "json", "sarif", "html", "csv", "pdf", "terminal"
    );

    private Reporters() { }

    public static List<Path> write(ScanResult result, String formats, Path outDir) throws IOException {
        Files.createDirectories(outDir);
        var written = new ArrayList<Path>();
        for (var format : formats.split(",")) {
            var fmt = format.trim().toLowerCase(Locale.ROOT);
            if (!KNOWN_FORMATS.contains(fmt)) {
                System.err.println("Unknown format: " + fmt);
                continue;
            }
            var path = switch (fmt) {
                case "json" -> writeJson(result, outDir);
                case "sarif" -> writeSarif(result, outDir);
                case "html" -> writeHtml(result, outDir);
                case "csv" -> writeCsv(result, outDir);
                case "pdf" -> writePdf(result, outDir);
                case "terminal" -> null;
                default -> null;
            };
            if (path != null) {
                written.add(path);
            }
        }
        return written;
    }

    private static Path writeJson(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.json");
        JSON.writeValue(path.toFile(), result);
        return path;
    }

    private static Path writeSarif(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.sarif");
        var rules = new ArrayList<Map<String, Object>>();
        var results = new ArrayList<Map<String, Object>>();
        var seen = new java.util.HashSet<String>();
        for (var f : result.findings()) {
            if (seen.add(f.controlId())) {
                rules.add(Map.of(
                    "id", f.controlId(),
                    "name", f.title(),
                    "shortDescription", Map.of("text", f.title()),
                    "fullDescription", Map.of("text", f.message()),
                    "helpUri", "https://github.com/conduktor/kafka-security-controls/blob/main/controls/"
                        + f.controlId() + ".md",
                    "defaultConfiguration", Map.of("level", sarifLevel(f.severity())),
                    "properties", Map.of(
                        "category", f.category().name(),
                        "severity", f.severity().name()
                    )
                ));
            }
            results.add(Map.of(
                "ruleId", f.controlId(),
                "level", sarifLevel(f.severity()),
                "message", Map.of("text", f.message()),
                "locations", List.of(Map.of(
                    "physicalLocation", Map.of(
                        "artifactLocation", Map.of("uri", "kafka://" + result.cluster().name())
                    )
                ))
            ));
        }
        var sarif = Map.of(
            "$schema", "https://json.schemastore.org/sarif-2.1.0.json",
            "version", "2.1.0",
            "runs", List.of(Map.of(
                "tool", Map.of("driver", Map.of(
                    "name", "kafka-security-scanner",
                    "version", "1.0.0",
                    "informationUri", "https://github.com/conduktor/kafka-security-scanner",
                    "rules", rules
                )),
                "results", results
            ))
        );
        JSON.writeValue(path.toFile(), sarif);
        return path;
    }

    private static String sarifLevel(Severity s) {
        return switch (s) {
            case critical, high -> "error";
            case medium -> "warning";
            case low, info -> "note";
        };
    }

    private static Path writeHtml(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.html");
        var sb = new StringBuilder(8192);
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.append("<title>Kafka Security Scan — ").append(escape(result.cluster().name())).append("</title>");
        sb.append("<style>");
        sb.append("body{font:14px -apple-system,BlinkMacSystemFont,'SF Pro Text',Helvetica,Arial,sans-serif;");
        sb.append("color:#1d1d1f;background:#f5f5f7;margin:0;padding:32px;}");
        sb.append(".container{max-width:1100px;margin:0 auto;background:#fff;border-radius:12px;");
        sb.append("padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.06);}");
        sb.append("h1{font-size:28px;margin:0 0 8px;font-weight:600;}");
        sb.append("h2{font-size:18px;margin:24px 0 12px;font-weight:600;}");
        sb.append(".meta{color:#6e6e73;font-size:13px;margin-bottom:24px;}");
        sb.append(".score{display:inline-block;padding:16px 24px;border-radius:8px;font-size:32px;");
        sb.append("font-weight:600;color:#fff;}");
        sb.append(".grade-A{background:#34c759;}.grade-B{background:#5ac8fa;}");
        sb.append(".grade-C{background:#ff9500;}.grade-F{background:#ff3b30;}");
        sb.append(".stats{display:flex;gap:16px;margin:16px 0;}");
        sb.append(".stat{flex:1;padding:12px;background:#f5f5f7;border-radius:8px;text-align:center;}");
        sb.append(".stat .v{font-size:24px;font-weight:600;}.stat .l{font-size:12px;color:#6e6e73;}");
        sb.append("details{border:1px solid #e5e5ea;border-radius:8px;margin:8px 0;padding:12px 16px;}");
        sb.append("details[open]{background:#fafafa;}");
        sb.append("summary{cursor:pointer;font-weight:500;list-style:none;}");
        sb.append("summary::-webkit-details-marker{display:none;}");
        sb.append("summary::before{content:'▶';margin-right:8px;font-size:10px;color:#86868b;}");
        sb.append("details[open] summary::before{content:'▼';}");
        sb.append(".sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;");
        sb.append("font-weight:600;text-transform:uppercase;margin-right:8px;}");
        sb.append(".sev-critical{background:#ff3b30;color:#fff;}");
        sb.append(".sev-high{background:#ff9500;color:#fff;}");
        sb.append(".sev-medium{background:#ffcc00;color:#1d1d1f;}");
        sb.append(".sev-low{background:#5ac8fa;color:#fff;}");
        sb.append(".sev-info{background:#8e8e93;color:#fff;}");
        sb.append(".rem{margin-top:8px;padding:8px 12px;background:#e8f4fd;border-left:3px solid #007aff;");
        sb.append("border-radius:4px;font-size:13px;}");
        sb.append("</style></head><body><div class=\"container\">");
        sb.append("<h1>Kafka Security Scan Report</h1>");
        sb.append("<div class=\"meta\">Cluster: <b>").append(escape(result.cluster().name()))
            .append("</b> · Scanned: ").append(escape(result.scannedAt()))
            .append(" · Brokers: ").append(result.cluster().brokers())
            .append(" · Topics: ").append(result.cluster().topics()).append("</div>");
        sb.append("<div class=\"score grade-").append(grade(result.score())).append("\">")
            .append(result.score()).append("/100</div>");
        sb.append("<div class=\"stats\">");
        sb.append("<div class=\"stat\"><div class=\"v\">").append(result.passCount())
            .append("</div><div class=\"l\">PASS</div></div>");
        sb.append("<div class=\"stat\"><div class=\"v\">").append(result.failCount())
            .append("</div><div class=\"l\">FAIL</div></div>");
        sb.append("<div class=\"stat\"><div class=\"v\">").append(result.naCount())
            .append("</div><div class=\"l\">N/A</div></div>");
        sb.append("<div class=\"stat\"><div class=\"v\">")
            .append(String.format(Locale.ROOT, "%.0f%%", result.passRate()))
            .append("</div><div class=\"l\">Pass Rate</div></div>");
        sb.append("</div>");
        sb.append("<h2>Findings (").append(result.findings().size()).append(")</h2>");
        var sorted = new ArrayList<>(result.findings());
        sorted.sort((a, b) -> severityOrder(b.severity()) - severityOrder(a.severity()));
        for (var f : sorted) {
            sb.append("<details><summary>")
                .append("<span class=\"sev sev-").append(f.severity().name()).append("\">")
                .append(f.severity().name()).append("</span>")
                .append("<b>").append(escape(f.controlId())).append("</b> — ")
                .append(escape(f.title())).append("</summary>");
            sb.append("<p>").append(escape(f.message())).append("</p>");
            if (f.remediation() != null && !f.remediation().isEmpty()) {
                sb.append("<div class=\"rem\"><b>Remediation:</b> ")
                    .append(escape(f.remediation())).append("</div>");
            }
            sb.append("</details>");
        }
        sb.append("</div></body></html>");
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
        return path;
    }

    private static Path writeCsv(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.csv");
        var sb = new StringBuilder(1024);
        sb.append("control_id,severity,category,status,title,message,remediation,")
            .append("pci_dss,soc2,iso27001\n");
        for (var f : result.findings()) {
            sb.append(csv(f.controlId())).append(',')
                .append(csv(f.severity().name())).append(',')
                .append(csv(f.category().name())).append(',')
                .append(csv(f.status())).append(',')
                .append(csv(f.title())).append(',')
                .append(csv(f.message())).append(',')
                .append(csv(f.remediation())).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().pciDss()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().soc2()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().iso27001())))
                .append('\n');
        }
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
        return path;
    }

    private static Path writePdf(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.pdf");
        try (var doc = new PDDocument()) {
            var cover = new PDPage();
            doc.addPage(cover);
            try (var cs = new PDPageContentStream(doc, cover)) {
                var bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                var regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                cs.beginText();
                cs.setFont(bold, 28);
                cs.newLineAtOffset(72, 720);
                cs.showText("Kafka Security Scan Report");
                cs.setFont(regular, 12);
                cs.newLineAtOffset(0, -40);
                cs.showText("Cluster: " + result.cluster().name());
                cs.newLineAtOffset(0, -16);
                cs.showText("Scanned: " + result.scannedAt());
                cs.newLineAtOffset(0, -16);
                cs.showText("Brokers: " + result.cluster().brokers()
                    + "  ·  Topics: " + result.cluster().topics());
                cs.newLineAtOffset(0, -32);
                cs.setFont(bold, 48);
                cs.showText("Score: " + result.score() + "/100  (" + grade(result.score()) + ")");
                cs.setFont(regular, 12);
                cs.newLineAtOffset(0, -32);
                cs.showText(String.format(Locale.ROOT,
                    "Pass: %d   Fail: %d   N/A: %d   Rate: %.1f%%",
                    result.passCount(), result.failCount(),
                    result.naCount(), result.passRate()));
                cs.newLineAtOffset(0, -200);
                cs.setFont(bold, 14);
                cs.showText("Sign-off");
                cs.setFont(regular, 11);
                cs.newLineAtOffset(0, -32);
                cs.showText("Reviewed by: ____________________________   Date: "
                    + LocalDate.now(ZoneId.systemDefault()));
                cs.newLineAtOffset(0, -24);
                cs.showText("Approved by: ____________________________   Date: ____________");
                cs.endText();
            }
            var findingsPage = new PDPage();
            doc.addPage(findingsPage);
            try (var cs = new PDPageContentStream(doc, findingsPage)) {
                var bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                var regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
                cs.beginText();
                cs.setFont(bold, 18);
                cs.newLineAtOffset(72, 750);
                cs.showText("Findings (" + result.findings().size() + ")");
                cs.setFont(regular, 9);
                var sorted = new ArrayList<>(result.findings());
                sorted.sort((a, b) -> severityOrder(b.severity()) - severityOrder(a.severity()));
                for (var f : sorted) {
                    cs.newLineAtOffset(0, -16);
                    cs.setFont(bold, 9);
                    cs.showText(f.severity().name().toUpperCase(Locale.ROOT) + "  " + f.controlId());
                    cs.setFont(regular, 9);
                    cs.newLineAtOffset(0, -12);
                    cs.showText(safe(f.title(), 90));
                    cs.newLineAtOffset(0, -10);
                    cs.showText("  " + safe(f.message(), 100));
                }
                cs.endText();
            }
            doc.save(path.toFile());
        }
        return path;
    }

    private static String csv(@Nullable String s) {
        if (s == null) {
            return "";
        }
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return '"' + s.replace("\"", "\"\"") + '"';
        }
        return s;
    }

    private static String joinList(@Nullable List<String> items) {
        if (items == null || items.isEmpty()) {
            return "";
        }
        return String.join(";", items);
    }

    private static String escape(@Nullable String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\"", "&quot;");
    }

    private static String safe(@Nullable String s, int max) {
        if (s == null) {
            return "";
        }
        var sanitized = s.replaceAll("[\\p{Cntrl}]", " ");
        return sanitized.length() <= max ? sanitized : sanitized.substring(0, max) + "...";
    }

    private static String grade(int score) {
        if (score >= 90) {
            return "A";
        }
        if (score >= 75) {
            return "B";
        }
        if (score >= 60) {
            return "C";
        }
        return "F";
    }

    private static int severityOrder(Severity s) {
        return switch (s) {
            case critical -> 4;
            case high -> 3;
            case medium -> 2;
            case low -> 1;
            case info -> 0;
        };
    }

    /** Pre-aggregate findings for callers that want a sorted snapshot. */
    public static List<Finding> sortedBySeverity(List<Finding> findings) {
        var sorted = new ArrayList<>(findings);
        sorted.sort((a, b) -> severityOrder(b.severity()) - severityOrder(a.severity()));
        return sorted;
    }

    /** Backwards-compat helper used by tests/Main to produce a quick summary map. */
    public static Map<String, Object> summary(ScanResult result) {
        var m = new LinkedHashMap<String, Object>();
        m.put("score", result.score());
        m.put("grade", grade(result.score()));
        m.put("pass", result.passCount());
        m.put("fail", result.failCount());
        m.put("na", result.naCount());
        return m;
    }
}
