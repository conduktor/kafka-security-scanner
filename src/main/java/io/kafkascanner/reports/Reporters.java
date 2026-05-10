package io.kafkascanner.reports;

import static io.kafkascanner.model.ScanModels.Finding;
import static io.kafkascanner.model.ScanModels.ScanResult;
import static io.kafkascanner.model.ScanModels.Severity;
import static io.kafkascanner.model.ScanModels.Status;

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
import org.apache.pdfbox.pdmodel.font.PDFont;
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
                "level", sarifLevelForStatus(f.severity(), f.status()),
                "message", Map.of("text",
                    "[" + f.status().name() + "] " + f.message()),
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

    private static String sarifLevelForStatus(Severity sev, Status status) {
        return switch (status) {
            case fail -> sarifLevel(sev);
            case na -> "warning";
            case error -> "error";
            default -> "note";
        };
    }

    private static Path writeHtml(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.html");
        var sb = new StringBuilder(8192);
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.append("<title>Kafka Security Scan — ").append(escape(result.cluster().name())).append("</title>");
        appendHtmlStyles(sb);
        var reportRows = resultsForAudit(result);
        var sorted = new ArrayList<>(reportRows);
        sorted.sort(Reporters::compareForAudit);
        var inScope = sorted.stream().filter(f -> !isOutOfScope(f)).count();
        var outOfScope = sorted.size() - inScope;
        sb.append("</head><body>");
        sb.append("<aside class=\"sidebar\">");
        sb.append("<div class=\"brand\">Kafka Security Scanner</div>");
        sb.append("<div class=\"side-title\">Scope</div>");
        appendFilterButton(sb, "scope", "in", "In Scope", inScope, true);
        appendFilterButton(sb, "scope", "out", "Out of Scope", outOfScope, false);
        sb.append("<div class=\"side-title\">Readiness</div>");
        appendFilterButton(sb, "status", "all", "All Statuses", inScope, true);
        appendFilterButton(sb, "status", "not-ready", "Not Ready", countByStatus(sorted, "not-ready"), false);
        appendFilterButton(sb, "status", "needs-evidence", "Needs Evidence",
            countByStatus(sorted, "needs-evidence"), false);
        appendFilterButton(sb, "status", "ready", "Ready", countByStatus(sorted, "ready"), false);
        sb.append("<div class=\"side-title\">Themes</div>");
        appendFilterButton(sb, "theme", "all", "All Themes", sorted.size(), true);
        for (var entry : themeCounts(sorted).entrySet()) {
            appendFilterButton(sb, "theme", slug(entry.getKey()), entry.getKey(), entry.getValue(), false);
        }
        sb.append("</aside>");

        sb.append("<main class=\"main\"><header class=\"topbar\">");
        sb.append("<button class=\"tab active\" data-tab=\"in\">In Scope <b>")
            .append(inScope).append("</b></button>");
        sb.append("<button class=\"tab\" data-tab=\"out\">Out of Scope <b>")
            .append(outOfScope).append("</b></button>");
        sb.append("<label class=\"search\"><span>Search</span><input id=\"control-search\" ")
            .append("placeholder=\"Search controls by name, code, evidence, or requirements\"></label>");
        sb.append("</header>");

        sb.append("<section class=\"summary\">");
        sb.append("<div><h1>Kafka Security Scan Report</h1><p>")
            .append("Cluster <b>").append(escape(result.cluster().name())).append("</b>")
            .append(" · Flavor ").append(escape(result.cluster().kafkaFlavor()))
            .append(" · Brokers ").append(result.cluster().brokers())
            .append(" · Topics ").append(result.cluster().topics())
            .append(" · Scanned ").append(escape(result.scannedAt()))
            .append("</p></div>");
        sb.append("<div class=\"score grade-").append(grade(result.score())).append("\">")
            .append(result.score()).append("<span>/100</span></div>");
        sb.append("</section>");
        sb.append("<section class=\"metrics\">");
        appendMetric(sb, "Pass", result.passCount(), "ready");
        appendMetric(sb, "Fail", result.failCount(), "not-ready");
        appendMetric(sb, "N/A", result.naCount(), "needs-evidence");
        appendMetric(sb, "Pass Rate", String.format(Locale.ROOT, "%.0f%%", result.passRate()), "neutral");
        sb.append("</section>");
        sb.append("<section class=\"collector-line\"><b>Collectors:</b> ")
            .append(escape(String.join(", ", result.collectorsUsed())));
        if (!result.collectorsUnavailable().isEmpty()) {
            sb.append(" <span><b>Missing evidence:</b> ")
                .append(escape(String.join(", ", result.collectorsUnavailable())))
                .append("</span>");
        }
        sb.append("</section>");

        sb.append("<section class=\"toolbar\"><button class=\"checkbox\" disabled></button>")
            .append("<span id=\"visible-count\"></span>")
            .append("<span class=\"muted\">Controls are grouped by audit scope and theme.</span>")
            .append("</section>");
        sb.append("<section class=\"control-list\">");
        for (var f : sorted) {
            appendControlRow(sb, f);
        }
        sb.append("</section></main>");
        appendHtmlScript(sb);
        sb.append("</body></html>");
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
        return path;
    }

    private static void appendHtmlStyles(StringBuilder sb) {
        sb.append("<style>");
        sb.append("*{box-sizing:border-box;}body{font:14px -apple-system,BlinkMacSystemFont,");
        sb.append("'SF Pro Text',Helvetica,Arial,sans-serif;color:#24262d;background:#f7f8fa;");
        sb.append("margin:0;display:grid;grid-template-columns:280px 1fr;min-height:100vh;}");
        sb.append(".sidebar{position:sticky;top:0;height:100vh;background:#fff;border-right:1px solid #dfe3e8;");
        sb.append("overflow:auto;padding:20px 16px;}.brand{font-size:18px;font-weight:700;margin:0 0 24px;}");
        sb.append(".side-title{font-size:12px;text-transform:uppercase;color:#6b7280;font-weight:700;");
        sb.append("letter-spacing:.03em;margin:20px 8px 8px;}.filter{width:100%;height:38px;border:0;");
        sb.append("background:transparent;border-radius:6px;display:flex;align-items:center;justify-content:space-between;");
        sb.append("padding:0 10px;color:#3f4350;font:inherit;cursor:pointer;text-align:left;}");
        sb.append(".filter:hover,.filter.active{background:#eef4ff;color:#245ca8;}.filter b{font-size:12px;color:#6b7280;}");
        sb.append(".main{min-width:0;background:#fff;}.topbar{height:64px;border-bottom:1px solid #dfe3e8;");
        sb.append("display:flex;align-items:stretch;background:#fff;position:sticky;top:0;z-index:2;}");
        sb.append(".tab{border:0;border-right:1px solid #dfe3e8;background:#fff;padding:0 22px;");
        sb.append("font:inherit;color:#606673;cursor:pointer;}.tab.active{color:#245ca8;box-shadow:inset 0 -2px #245ca8;}");
        sb.append(".tab b{margin-left:6px;}.search{flex:1;display:flex;align-items:center;gap:12px;padding:0 22px;");
        sb.append("color:#6b7280;}.search input{width:100%;border:0;outline:0;font:inherit;color:#24262d;}");
        sb.append(".summary{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;");
        sb.append("padding:28px 32px 18px;border-bottom:1px solid #edf0f3;}.summary h1{font-size:28px;");
        sb.append("line-height:1.2;margin:0 0 8px;}.summary p{margin:0;color:#626875;}");
        sb.append(".score{min-width:116px;text-align:center;padding:14px 18px;border-radius:8px;font-size:30px;");
        sb.append("font-weight:800;color:#fff;}.score span{font-size:16px;font-weight:700;}");
        sb.append(".grade-A{background:#1f9d47;}.grade-B{background:#2386c8;}.grade-C{background:#d98219;}");
        sb.append(".grade-F{background:#d83333;}.metrics{display:grid;grid-template-columns:repeat(4,minmax(120px,1fr));");
        sb.append("gap:12px;padding:18px 32px;}.metric{border:1px solid #e6e9ee;border-radius:6px;padding:14px 16px;}");
        sb.append(".metric b{font-size:22px;display:block;}.metric span{font-size:12px;color:#626875;text-transform:uppercase;}");
        sb.append(".collector-line{padding:0 32px 18px;color:#626875;}.collector-line span{display:block;margin-top:6px;}");
        sb.append(".toolbar{height:52px;border-top:1px solid #edf0f3;border-bottom:1px solid #dfe3e8;");
        sb.append("display:flex;align-items:center;gap:14px;padding:0 32px;color:#626875;}.checkbox{width:20px;height:20px;");
        sb.append("border:2px solid #9aa0aa;border-radius:3px;background:#fff;}.control-list{background:#fff;}");
        sb.append(".control-row{border:0;border-bottom:1px solid #dfe3e8;background:#fff;}");
        sb.append(".control-row[open]{background:#fbfcfd;}.control-row[hidden]{display:none;}");
        sb.append(".control-row summary{list-style:none;display:grid;grid-template-columns:28px 34px 1fr auto;");
        sb.append("gap:16px;align-items:center;min-height:96px;padding:16px 32px;cursor:pointer;}");
        sb.append(".control-row summary::-webkit-details-marker{display:none;}.status-dot{width:34px;height:34px;border-radius:50%;");
        sb.append("display:grid;place-items:center;font-weight:800;}.dot-ready{background:#e9f9e8;color:#199b23;}");
        sb.append(".dot-not-ready{background:#ffecec;color:#cf2029;}.dot-needs-evidence{background:#f1f3f6;color:#6b7280;}");
        sb.append(".dot-out-scope{background:#f1f3f6;color:#6b7280;}.code{color:#245ca8;font-weight:700;margin-right:8px;}");
        sb.append(".row-title{font-weight:700;font-size:16px;}.row-main p{margin:6px 0 10px;color:#424752;}");
        sb.append(".chips{display:flex;flex-wrap:wrap;gap:6px;}.chip{border-radius:5px;background:#eef2f7;color:#445063;");
        sb.append("padding:4px 8px;font-size:12px;font-weight:600;}.chip.theme{background:#eef4ff;color:#245ca8;}");
        sb.append(".chip.scope{background:#f1f3f6;color:#626875;}.badge{border-radius:5px;color:#fff;font-weight:800;");
        sb.append("font-size:12px;text-transform:uppercase;padding:5px 9px;white-space:nowrap;}");
        sb.append(".sev-critical{background:#d83333;}.sev-high{background:#d98219;}.sev-medium{background:#e9b949;color:#1f2937;}");
        sb.append(".sev-low{background:#2386c8;}.sev-info,.sev-na{background:#858b96;}.sev-pass{background:#1f9d47;}");
        sb.append(".detail{padding:0 32px 20px 110px;}.rem{margin:0 0 12px;padding:10px 12px;");
        sb.append("background:#e8f4fd;border-left:3px solid #007aff;border-radius:4px;}.detail pre{white-space:pre-wrap;");
        sb.append("background:#f3f5f7;border-radius:6px;padding:12px;font-size:12px;line-height:1.4;overflow:auto;}");
        sb.append(".muted{color:#8a9099;}@media(max-width:900px){body{display:block}.sidebar{position:relative;");
        sb.append("height:auto;border-right:0;border-bottom:1px solid #dfe3e8}.topbar{top:0}.metrics{grid-template-columns:repeat(2,1fr)}");
        sb.append(".control-row summary{grid-template-columns:24px 28px 1fr;}.badge{grid-column:3}.detail{padding-left:32px}}");
        sb.append("</style>");
    }

    private static void appendMetric(StringBuilder sb, String label, Object value, String cssClass) {
        sb.append("<div class=\"metric ").append(escape(cssClass)).append("\"><b>")
            .append(escape(String.valueOf(value))).append("</b><span>")
            .append(escape(label)).append("</span></div>");
    }

    private static void appendFilterButton(
        StringBuilder sb,
        String filter,
        String value,
        String label,
        long count,
        boolean active
    ) {
        sb.append("<button class=\"filter");
        if (active) {
            sb.append(" active");
        }
        sb.append("\" data-filter=\"").append(escape(filter)).append("\" data-value=\"")
            .append(escape(value)).append("\"><span>").append(escape(label))
            .append("</span><b>").append(count).append("</b></button>");
    }

    private static void appendControlRow(StringBuilder sb, Finding finding) throws IOException {
        var outOfScope = isOutOfScope(finding);
        var scope = outOfScope ? "out" : "in";
        var readiness = readiness(finding);
        var theme = themeFor(finding);
        sb.append("<details class=\"control-row status-").append(escape(finding.status().name()))
            .append("\" data-scope=\"").append(scope)
            .append("\" data-status=\"").append(escape(readiness))
            .append("\" data-theme=\"").append(escape(slug(theme)))
            .append("\" data-search=\"").append(escape(searchText(finding, theme))).append("\">");
        sb.append("<summary><span class=\"checkbox\"></span><span class=\"status-dot dot-")
            .append(escape(readiness)).append("\">").append(escape(statusIcon(readiness)))
            .append("</span><div class=\"row-main\"><div><span class=\"code\">")
            .append(escape(finding.controlId())).append("</span><span class=\"row-title\">")
            .append(escape(finding.title())).append("</span></div><p>")
            .append(escape(finding.message())).append("</p><div class=\"chips\">");
        sb.append("<span class=\"chip theme\">").append(escape(theme)).append("</span>");
        sb.append("<span class=\"chip scope\">").append(outOfScope ? "Out of Scope" : "In Scope")
            .append("</span>");
        appendComplianceChips(sb, finding);
        sb.append("</div></div><span class=\"badge ").append(escape(badgeClass(finding)))
            .append("\">").append(escape(badgeText(finding))).append("</span></summary>");
        sb.append("<div class=\"detail\">");
        if (shouldShowRemediation(finding)
            && finding.remediation() != null
            && !finding.remediation().isEmpty()) {
            sb.append("<div class=\"rem\"><b>Remediation:</b> ")
                .append(escape(finding.remediation())).append("</div>");
        }
        if (finding.evidence() != null && !finding.evidence().isEmpty()) {
            sb.append("<pre>").append(escape(JSON.writeValueAsString(finding.evidence())))
                .append("</pre>");
        }
        sb.append("</div></details>");
    }

    private static void appendComplianceChips(StringBuilder sb, Finding finding) {
        var compliance = finding.compliance();
        if (compliance == null) {
            return;
        }
        if (!compliance.pciDss().isEmpty()) {
            sb.append("<span class=\"chip\">PCI DSS</span>");
        }
        if (!compliance.soc2().isEmpty()) {
            sb.append("<span class=\"chip\">SOC 2</span>");
        }
        if (!compliance.iso27001().isEmpty()) {
            sb.append("<span class=\"chip\">ISO 27001</span>");
        }
        if (!compliance.nist().isEmpty()) {
            sb.append("<span class=\"chip\">NIST</span>");
        }
        if (!compliance.cwe().isEmpty()) {
            sb.append("<span class=\"chip\">CWE</span>");
        }
    }

    private static void appendHtmlScript(StringBuilder sb) {
        sb.append("<script>");
        sb.append("(()=>{let scope='in',theme='all',status='all';");
        sb.append("const rows=[...document.querySelectorAll('.control-row')];");
        sb.append("const search=document.getElementById('control-search');");
        sb.append("function mark(sel,attr,val){document.querySelectorAll(sel).forEach(b=>");
        sb.append("b.classList.toggle('active',b.dataset[attr]===val));}");
        sb.append("function update(){const q=(search.value||'').toLowerCase();let visible=0;");
        sb.append("rows.forEach(r=>{const ok=r.dataset.scope===scope&&(theme==='all'||r.dataset.theme===theme)");
        sb.append("&&(status==='all'||r.dataset.status===status)&&(!q||r.dataset.search.includes(q));");
        sb.append("r.hidden=!ok;if(ok)visible++;});");
        sb.append("document.getElementById('visible-count').textContent=visible+' controls shown';");
        sb.append("mark('.tab','tab',scope);mark('[data-filter=\"scope\"]','value',scope);");
        sb.append("mark('[data-filter=\"theme\"]','value',theme);mark('[data-filter=\"status\"]','value',status);}");
        sb.append("document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>{scope=b.dataset.tab;update();}));");
        sb.append("document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{");
        sb.append("const f=b.dataset.filter;if(f==='scope')scope=b.dataset.value;");
        sb.append("if(f==='theme')theme=b.dataset.value;if(f==='status')status=b.dataset.value;update();}));");
        sb.append("search.addEventListener('input',update);update();})();");
        sb.append("</script>");
    }

    private static Path writeCsv(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.csv");
        var sb = new StringBuilder(1024);
        sb.append("control_id,severity,category,status,title,message,remediation,")
            .append("pci_dss,soc2,iso27001,nist,cwe,evidence\n");
        for (var f : resultsForAudit(result)) {
            sb.append(csv(f.controlId())).append(',')
                .append(csv(f.severity().name())).append(',')
                .append(csv(f.category().name())).append(',')
                .append(csv(f.status().name())).append(',')
                .append(csv(f.title())).append(',')
                .append(csv(f.message())).append(',')
                .append(csv(f.remediation())).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().pciDss()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().soc2()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().iso27001()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().nist()))).append(',')
                .append(csv(joinList(f.compliance() == null ? null : f.compliance().cwe()))).append(',')
                .append(csv(JSON.writeValueAsString(f.evidence())))
                .append('\n');
        }
        Files.writeString(path, sb.toString(), StandardCharsets.UTF_8);
        return path;
    }

    private static Path writePdf(ScanResult result, Path outDir) throws IOException {
        var path = outDir.resolve("report.pdf");
        try (var doc = new PDDocument()) {
            var bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
            var regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
            writePdfCover(doc, result, bold, regular);
            writePdfFindings(doc, result, bold, regular);
            doc.save(path.toFile());
        }
        return path;
    }

    private static void writePdfCover(PDDocument doc, ScanResult result, PDFont bold, PDFont regular)
        throws IOException {
        var cover = new PDPage();
        doc.addPage(cover);
        try (var cs = new PDPageContentStream(doc, cover)) {
            cs.beginText();
            cs.setFont(bold, 28);
            cs.newLineAtOffset(72, 720);
            cs.showText("Kafka Security Scan Report");
            cs.setFont(regular, 12);
            cs.newLineAtOffset(0, -40);
            cs.showText(safe("Cluster: " + result.cluster().name(), 90));
            cs.newLineAtOffset(0, -16);
            cs.showText(safe("Scanned: " + result.scannedAt(), 90));
            cs.newLineAtOffset(0, -16);
            cs.showText("Brokers: " + result.cluster().brokers()
                + "  .  Topics: " + result.cluster().topics());
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
    }

    private static void writePdfFindings(PDDocument doc, ScanResult result, PDFont bold, PDFont regular)
        throws IOException {
        var sorted = new ArrayList<>(result.findings());
        sorted.sort((a, b) -> severityOrder(b.severity()) - severityOrder(a.severity()));
        try (var page = new PdfFindingPage(doc, bold, regular, result.findings().size())) {
            for (var f : sorted) {
                page.ensureSpace(48);
                page.line(f.severity().name().toUpperCase(Locale.ROOT) + "  " + f.controlId(), bold, 9, 16);
                page.line(safe(f.title(), 90), regular, 9, 12);
                page.line("  " + safe(f.message(), 100), regular, 9, 20);
            }
        }
    }

    private static final class PdfFindingPage implements AutoCloseable {
        private static final float X = 72;
        private static final float TOP_Y = 750;
        private static final float BOTTOM_Y = 72;

        private final PDDocument doc;
        private final PDFont bold;
        private final PDFont regular;
        private final int findingCount;
        private @Nullable PDPageContentStream content;
        private float y;

        PdfFindingPage(PDDocument doc, PDFont bold, PDFont regular, int findingCount) throws IOException {
            this.doc = doc;
            this.bold = bold;
            this.regular = regular;
            this.findingCount = findingCount;
            openPage();
        }

        void ensureSpace(float height) throws IOException {
            if (y - height < BOTTOM_Y) {
                openPage();
            }
        }

        void line(String text, PDFont font, int size, float leading) throws IOException {
            var current = content;
            if (current == null) {
                throw new IllegalStateException("PDF page is not open");
            }
            current.beginText();
            current.setFont(font, size);
            current.newLineAtOffset(X, y);
            current.showText(safe(text, 115));
            current.endText();
            y -= leading;
        }

        @Override
        public void close() throws IOException {
            var current = content;
            if (current != null) {
                current.close();
            }
        }

        private void openPage() throws IOException {
            var current = content;
            if (current != null) {
                current.close();
            }
            var page = new PDPage();
            doc.addPage(page);
            content = new PDPageContentStream(doc, page);
            y = TOP_Y;
            line("Findings (" + findingCount + ")", bold, 18, 26);
            line("Severity  Control", regular, 9, 16);
        }
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
        // PDFBox Helvetica only ships WinAnsi (Latin-1 + a few specials). Drop
        // characters outside that range — covers Unicode em-dashes / U+2264
        // ('lessequal') / smart quotes that sneak into control titles.
        var sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') {
                sb.append(' ');
            } else if (c < 0x20 || c == 0x7f) {
                sb.append(' ');
            } else if (c >= 0x100) {
                // approximate the most common offenders so the message is still readable
                sb.append(switch (c) {
                    case '≤' -> "<=";
                    case '≥' -> ">=";
                    case '—', '–' -> "-";
                    case '“', '”', '«', '»' -> "\"";
                    case '‘', '’' -> "'";
                    case '·', '•' -> ".";
                    case '→', '←' -> "->";
                    default -> "?";
                });
            } else {
                sb.append(c);
            }
        }
        var sanitized = sb.toString();
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
        sorted.sort(Reporters::compareForAudit);
        return sorted;
    }

    private static int compareForAudit(Finding a, Finding b) {
        int statusCompare = statusOrder(a.status()) - statusOrder(b.status());
        if (statusCompare != 0) {
            return statusCompare;
        }
        return severityOrder(b.severity()) - severityOrder(a.severity());
    }

    private static int statusOrder(Status status) {
        return switch (status) {
            case fail -> 0;
            case error -> 1;
            case na -> 2;
            case pass -> 3;
            case covered_by_flavor -> 4;
        };
    }

    private static String badgeText(Finding finding) {
        if (isOutOfScope(finding)) {
            return "N/A";
        }
        return switch (finding.status()) {
            case fail -> finding.severity().name().toUpperCase(Locale.ROOT);
            case error -> "ERROR";
            case na -> "N/A";
            case pass -> "PASS";
            case covered_by_flavor -> "COVERED";
        };
    }

    private static String badgeClass(Finding finding) {
        if (isOutOfScope(finding)) {
            return "sev-na";
        }
        return switch (finding.status()) {
            case fail -> "sev-" + finding.severity().name();
            case error -> "sev-critical";
            case na -> "sev-na";
            case pass, covered_by_flavor -> "sev-pass";
        };
    }

    private static boolean shouldShowRemediation(Finding finding) {
        return finding.status() == Status.fail || finding.status() == Status.error;
    }

    private static boolean isOutOfScope(Finding finding) {
        return finding.evidence() != null
            && Boolean.TRUE.equals(finding.evidence().get("not_applicable"));
    }

    private static String readiness(Finding finding) {
        if (isOutOfScope(finding)) {
            return "out-scope";
        }
        return switch (finding.status()) {
            case pass, covered_by_flavor -> "ready";
            case fail, error -> "not-ready";
            case na -> "needs-evidence";
        };
    }

    private static String statusIcon(String readiness) {
        return switch (readiness) {
            case "ready" -> "OK";
            case "not-ready" -> "!";
            case "needs-evidence" -> "?";
            case "out-scope" -> "-";
            default -> "";
        };
    }

    private static long countByStatus(List<Finding> findings, String readiness) {
        return findings.stream()
            .filter(f -> !isOutOfScope(f))
            .filter(f -> readiness.equals(readiness(f)))
            .count();
    }

    private static Map<String, Long> themeCounts(List<Finding> findings) {
        var counts = new LinkedHashMap<String, Long>();
        for (var theme : List.of(
            "Authentication",
            "Authorization",
            "Data Protection",
            "Network & Platform",
            "Auditability",
            "Monitoring",
            "Operations",
            "Ecosystem Services",
            "Governance Evidence")) {
            counts.put(theme, 0L);
        }
        for (var finding : findings) {
            var theme = themeFor(finding);
            counts.put(theme, counts.getOrDefault(theme, 0L) + 1L);
        }
        counts.entrySet().removeIf(e -> e.getValue() == 0L);
        return counts;
    }

    private static String themeFor(Finding finding) {
        var id = finding.controlId() == null ? "" : finding.controlId().toUpperCase(Locale.ROOT);
        if (id.contains("-AUTH-")) {
            return "Authentication";
        }
        if (id.contains("-ACL-") || id.contains("-RBAC-") || id.contains("-OAUTH-")
            || id.contains("-IAM-") || id.contains("-DELEGATION-")) {
            return "Authorization";
        }
        if (id.contains("-ENC-") || id.contains("-TLS-") || id.contains("-KMS-")
            || id.contains("-DATA-") || id.contains("-SR-")) {
            return "Data Protection";
        }
        if (id.contains("-NET-") || id.contains("-KRAFT-") || id.contains("-ZK-")
            || id.contains("-K8S-") || id.contains("-GCP-") || id.contains("-AWS-")
            || id.contains("-AZURE-") || id.contains("-AIVEN-") || id.contains("-RP-")
            || id.contains("-CC-")) {
            return "Network & Platform";
        }
        if (id.contains("-AUDIT-")) {
            return "Auditability";
        }
        if (id.contains("-MON-") || id.contains("-SIEM-") || id.contains("-ALERT-")) {
            return "Monitoring";
        }
        if (id.contains("-CONNECT-") || id.contains("-REST-") || id.contains("-STREAMS-")) {
            return "Ecosystem Services";
        }
        if (id.contains("-OPS-") || id.contains("-JMX-") || id.contains("-PROCESS-")
            || id.contains("-FS-") || id.contains("-CIS-")) {
            return "Operations";
        }
        return "Governance Evidence";
    }

    private static String slug(String value) {
        return value.toLowerCase(Locale.ROOT)
            .replace("&", "and")
            .replaceAll("[^a-z0-9]+", "-")
            .replaceAll("(^-|-$)", "");
    }

    private static String searchText(Finding finding, String theme) {
        var sb = new StringBuilder();
        sb.append(nullToEmpty(finding.controlId())).append(' ')
            .append(nullToEmpty(finding.title())).append(' ')
            .append(nullToEmpty(finding.message())).append(' ')
            .append(nullToEmpty(finding.remediation())).append(' ')
            .append(theme).append(' ')
            .append(finding.status().name());
        var evidence = finding.evidence();
        if (evidence != null) {
            sb.append(' ').append(String.valueOf(evidence.getOrDefault("condition", "")))
                .append(' ').append(String.valueOf(evidence.getOrDefault("requires", "")))
                .append(' ').append(String.valueOf(evidence.getOrDefault("missing_collectors", "")));
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static List<Finding> resultsForAudit(ScanResult result) {
        return result.controlResults().isEmpty() ? result.findings() : result.controlResults();
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
