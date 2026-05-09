package io.kafkascanner.collectors;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads {@code --docs-dir}: governance artifacts that prove process controls.
 *
 * <p>Each artifact is a single file; the collector exposes presence and age
 * (days since last modified) so controls can write conditions like
 * {@code docs.dr_drill_log.exists && docs.dr_drill_log.age_days <= 90}.
 *
 * <p>Expected files (all optional):
 * <ul>
 *   <li>{@code dr-drill-log.md} — last DR drill</li>
 *   <li>{@code incident-response.md} — runbook</li>
 *   <li>{@code acl-review-log.md} — last ACL audit</li>
 *   <li>{@code patching-log.md} — last patching round</li>
 *   <li>{@code data-classification.md} — topic classification map</li>
 *   <li>{@code key-rotation-log.md} — last key rotation</li>
 *   <li>{@code iac.repo} — pointer to the IaC repo (presence proves IaC adoption)</li>
 *   <li>{@code monitoring-alerts.md} — auth-failure / acl-denial / quota alert config</li>
 *   <li>{@code dlq-config.md} — Connect/Streams DLQ topology</li>
 * </ul>
 *
 * <p>This is not a perfect proof — a touched file can be backdated. But it
 * forces the operator to produce an artifact that can be code-reviewed and
 * git-history-checked. Better than a yes/no in a properties file.
 */
public final class DocsCollector implements Collector {

    private static final String[] EXPECTED = {
        "dr_drill_log",
        "incident_response",
        "acl_review_log",
        "patching_log",
        "data_classification",
        "data_masking",
        "key_rotation_log",
        "iac",
        "monitoring_alerts",
        "dlq_config",
        "transactional_acls",
        "delegation_token_policy",
        "tenant_principal_map",
        "oauth_token_policy",
        "schema_auth_policy",
        "schema_audit_log",
        "streams_state_encryption",
        "streams_security_policy",
        "rbac_policy",
        "principal_mapping_rules",
        "audit_retention",
        "audit_pipeline",
        "connect_audit_policy",
        "backup_encryption",
        "network_topology",
        "disk_encryption_evidence",
        "admin_principals",
    };

    @Override
    public String name() {
        return "docs";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        if (!context.hasDocsDir()) {
            return false;
        }
        return Files.isDirectory(Path.of(context.docsDir()));
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var dir = Path.of(context.docsDir());
        var out = new HashMap<String, Object>();
        out.put("docs_dir", dir.toString());
        for (var name : EXPECTED) {
            out.put(name, inspect(dir, name));
        }
        return Map.of("docs", out);
    }

    private static Map<String, Object> inspect(Path dir, String name) {
        var info = new HashMap<String, Object>();
        // Look for snake_case (key) and kebab-case (filename) variants.
        var dashed = name.replace('_', '-');
        Path candidate = null;
        for (var stem : new String[] {name, dashed}) {
            for (var ext : new String[] {".md", ".txt", ""}) {
                var p = dir.resolve(stem + ext);
                if (Files.exists(p)) {
                    candidate = p;
                    break;
                }
            }
            if (candidate != null) {
                break;
            }
        }
        if (candidate == null) {
            info.put("exists", false);
            info.put("age_days", -1L);
            info.put("size", 0L);
            return info;
        }
        info.put("exists", true);
        info.put("path", candidate.toString());
        try {
            var mtime = Files.getLastModifiedTime(candidate).toInstant();
            info.put("age_days", ChronoUnit.DAYS.between(mtime, Instant.now()));
            info.put("size", Files.size(candidate));
        } catch (IOException e) {
            info.put("age_days", -1L);
            info.put("size", 0L);
        }
        if ("admin_principals".equals(name)) {
            info.put("principals", parsePrincipals(candidate));
        }
        return info;
    }

    /**
     * Pulls Kafka principal entries (User:..., Group:...) from a docs file. Lines
     * starting with {@code #} are ignored; everything else is scanned for the
     * first principal-shaped token so authors can write either bullet lists,
     * tables, or plain enumerations.
     */
    private static List<String> parsePrincipals(Path file) {
        var out = new ArrayList<String>();
        try {
            for (var raw : Files.readAllLines(file)) {
                var line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                for (var prefix : new String[] {"User:", "Group:"}) {
                    int idx = line.indexOf(prefix);
                    if (idx < 0) {
                        continue;
                    }
                    int end = idx + prefix.length();
                    while (end < line.length()) {
                        char c = line.charAt(end);
                        if (Character.isWhitespace(c) || c == ',' || c == ';'
                            || c == '|' || c == '`' || c == '"' || c == '\'') {
                            break;
                        }
                        end++;
                    }
                    var principal = line.substring(idx, end);
                    if (principal.length() > prefix.length() && !out.contains(principal)) {
                        out.add(principal);
                    }
                }
            }
        } catch (IOException e) {
            // best-effort; missing/unreadable file leaves the list empty
        }
        return out;
    }
}
