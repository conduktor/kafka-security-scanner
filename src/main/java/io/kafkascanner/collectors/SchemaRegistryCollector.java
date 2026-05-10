package io.kafkascanner.collectors;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Probes Confluent Schema Registry. Pass {@code --schema-registry-url
 * http://host:8081}. Populates {@code schemaregistry}.
 */
public final class SchemaRegistryCollector implements Collector {

    @Override
    public String name() {
        return "schemaregistry";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.hasSchemaRegistryUrl();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var url = context.schemaRegistryUrl();
        if (url == null) {
            return Map.of();
        }
        var base = url.replaceAll("/+$", "");
        var rootResp = HttpProbe.get(base + "/subjects", context.timeout());
        var out = new HashMap<String, Object>(rootResp);

        var subjects = rootResp.get("body");
        boolean subjectsEnumerated = subjects instanceof List<?>;
        out.put("subjects_enumerated", subjectsEnumerated);
        out.put("subject_count_unknown", !subjectsEnumerated);
        if (subjects instanceof List<?> list) {
            out.put("subject_count", (long) list.size());
        } else {
            out.put("subject_count", 0L);
        }

        var configResp = HttpProbe.get(base + "/config", context.timeout());
        var configBody = configResp.get("body");
        if (configBody instanceof Map<?, ?> m) {
            var compat = String.valueOf(m.get("compatibilityLevel"));
            out.put("compatibility_level", compat);
            // Compatibility modes that prevent breaking changes for consumers.
            out.put("compatibility_protects_consumers",
                compat.toUpperCase(Locale.ROOT).startsWith("BACKWARD")
                    || compat.toUpperCase(Locale.ROOT).equals("FULL")
                    || compat.toUpperCase(Locale.ROOT).startsWith("FULL_"));
        } else {
            out.put("compatibility_level", "UNKNOWN");
            out.put("compatibility_protects_consumers", false);
        }

        // Per-subject inspection: pull the latest version, scan the schema text
        // for encryption / tokenization / owner annotations and probe whether
        // anonymous registration is allowed (proves schema-registry RBAC).
        var subjectDetails = new ArrayList<Map<String, Object>>();
        boolean anyEncrypt = false;
        boolean anyTokenized = false;
        boolean anyOwner = false;
        boolean writeAnonAllowed = false;
        boolean writeProbePerformed = context.activeProbesAllowed();
        out.put("write_probe_performed", writeProbePerformed);
        out.put("write_probe_mode", writeProbePerformed
            ? "active_opt_in"
            : "disabled_non_mutating_default");
        var subjectNames = new ArrayList<String>();
        if (subjects instanceof List<?> list) {
            for (var s : list) {
                if (s instanceof String name) {
                    subjectNames.add(name);
                }
            }
        }
        boolean allSubjectsRequireAuth = subjectsEnumerated && !subjectNames.isEmpty();
        for (var name : subjectNames) {
            var verResp = HttpProbe.get(base + "/subjects/" + urlEncode(name) + "/versions/latest",
                context.timeout());
            var verBody = verResp.get("body");
            var entry = new HashMap<String, Object>();
            entry.put("name", name);
            if (verBody instanceof Map<?, ?> vm) {
                var schema = String.valueOf(vm.get("schema"));
                var schemaType = vm.get("schemaType") == null
                    ? "AVRO" : String.valueOf(vm.get("schemaType"));
                entry.put("schema_type", schemaType);
                entry.put("schema_size", (long) schema.length());
                boolean enc = containsAny(schema, "@encrypt", "x-encryption", "\"encrypted\":true",
                    "\"encrypt\":true", "confluent:tags", "PII", "pii");
                boolean tok = containsAny(schema, "@tokenize", "@tokenized", "x-tokenization",
                    "\"tokenized\":true", "\"tokenize\":true");
                boolean own = containsAny(schema, "\"owner\"", "x-owner", "@owner", "doc-owner");
                entry.put("annotation_encrypt", enc);
                entry.put("annotation_tokenized", tok);
                entry.put("annotation_owner", own);
                if (enc) {
                    anyEncrypt = true;
                }
                if (tok) {
                    anyTokenized = true;
                }
                if (own) {
                    anyOwner = true;
                }
            } else {
                entry.put("schema_type", "UNKNOWN");
                entry.put("annotation_encrypt", false);
                entry.put("annotation_tokenized", false);
                entry.put("annotation_owner", false);
            }

            if (writeProbePerformed) {
                // Active probe: POST without creds. Status 401/403 is the
                // only safe outcome. Disabled by default because a permissive
                // registry can register the schema version.
                var writeProbe = HttpProbe.post(
                    base + "/subjects/" + urlEncode(name) + "/versions",
                    "{\"schema\":\"\\\"int\\\"\"}",
                    "application/vnd.schemaregistry.v1+json",
                    context.timeout());
                boolean reqAuth = Boolean.TRUE.equals(writeProbe.get("requires_auth"));
                boolean anon = !reqAuth
                    && Boolean.TRUE.equals(writeProbe.get("reachable"));
                entry.put("write_anonymous_allowed", anon);
                entry.put("write_requires_auth", reqAuth);
                entry.put("write_status", writeProbe.get("status"));
                if (anon) {
                    writeAnonAllowed = true;
                }
                if (!reqAuth) {
                    allSubjectsRequireAuth = false;
                }
            } else {
                entry.put("write_anonymous_allowed", false);
                entry.put("write_requires_auth", false);
                entry.put("write_status", "not_probed");
                entry.put("write_probe_skipped_reason", "active probes disabled");
                allSubjectsRequireAuth = false;
            }

            subjectDetails.add(entry);
        }
        out.put("subject_details", subjectDetails);
        out.put("any_subject_with_encrypt_annotation", anyEncrypt);
        out.put("any_subject_with_tokenized_annotation", anyTokenized);
        out.put("any_subject_with_owner_annotation", anyOwner);
        out.put("write_anonymous_allowed", writeAnonAllowed);
        out.put("all_subjects_require_auth", allSubjectsRequireAuth);

        return Map.of("schemaregistry", out);
    }

    private static boolean containsAny(String hay, String... needles) {
        if (hay == null) {
            return false;
        }
        var lower = hay.toLowerCase(Locale.ROOT);
        for (var n : needles) {
            if (lower.contains(n.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8)
            .replace("+", "%20");
    }
}
