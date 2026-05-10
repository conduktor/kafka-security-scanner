package io.kafkascanner.policy;

import static io.kafkascanner.model.ScanModels.ClusterInfo;
import static io.kafkascanner.model.ScanModels.Control;
import static io.kafkascanner.model.ScanModels.Finding;
import static io.kafkascanner.model.ScanModels.Policy;
import static io.kafkascanner.model.ScanModels.ScanResult;
import static io.kafkascanner.model.ScanModels.Status;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import dev.cel.common.types.ListType;
import dev.cel.common.types.MapType;
import dev.cel.common.types.SimpleType;
import dev.cel.compiler.CelCompiler;
import dev.cel.compiler.CelCompilerFactory;
import dev.cel.parser.CelStandardMacro;
import dev.cel.runtime.CelRuntime;
import dev.cel.runtime.CelRuntimeFactory;
import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Loads policy YAML and evaluates CEL conditions against the collected snapshot.
 *
 * <p>A control resolves in this order:
 * <ol>
 *   <li>{@code covered_by_kafka_flavor} matches detected flavor → {@code covered_by_flavor}</li>
 *   <li>{@code requires} list contains a collector that did not run → {@code na}</li>
 *   <li>CEL {@code condition} evaluates to bool → {@code pass}/{@code fail}</li>
 * </ol>
 *
 * <p>Every control must declare a real CEL condition or {@code covered_by_kafka_flavor}.
 * Manual attestation is intentionally not a valid resolution: {@link #load(File)} rejects
 * placeholder policies at load time so the scanner never claims a pass it can't prove.
 */
public final class PolicyEngine {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory())
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final Map<String, Integer> WEIGHTS = Map.of(
        "critical", 15, "high", 10, "medium", 5, "low", 2, "info", 0
    );
    private static final Set<String> ADMIN_CLIENT_VARS = Set.of(
        "brokers", "topics", "acls", "acl_meta", "topic_meta",
        "quotas", "quota_meta", "cluster"
    );
    private static final Map<String, String> ADMIN_CLIENT_VAR_TO_DATA_KEY = Map.of(
        "brokers", "broker",
        "topics", "topic",
        "acls", "acl",
        "acl_meta", "acl",
        "topic_meta", "topic",
        "quotas", "quota",
        "quota_meta", "quota",
        "cluster", "kraft"
    );
    private static final Map<String, String> POLICY_VAR_TO_DATA_KEY = Map.ofEntries(
        Map.entry("brokers", "broker"),
        Map.entry("topics", "topic"),
        Map.entry("topic_meta", "topic_metadata"),
        Map.entry("acls", "acl"),
        Map.entry("acl_meta", "acl_metadata"),
        Map.entry("quotas", "quota"),
        Map.entry("quota_meta", "quota_metadata"),
        Map.entry("cluster", "kraft"),
        Map.entry("jmx", "jmx"),
        Map.entry("fs", "fs"),
        Map.entry("tls", "tls"),
        Map.entry("process", "process"),
        Map.entry("connect", "connect"),
        Map.entry("schemaregistry", "schemaregistry"),
        Map.entry("restproxy", "restproxy"),
        Map.entry("docs", "docs"),
        Map.entry("alerts", "alerts"),
        Map.entry("siem", "siem"),
        Map.entry("zk", "zk"),
        Map.entry("consumer_jmx", "consumer_jmx"),
        Map.entry("kms", "kms"),
        Map.entry("cc", "cc"),
        Map.entry("aws", "aws"),
        Map.entry("cis", "cis"),
        Map.entry("aiven", "aiven"),
        Map.entry("rpcloud", "rpcloud"),
        Map.entry("azure", "azure"),
        Map.entry("k8s", "k8s"),
        Map.entry("gcp", "gcp"),
        Map.entry("streams", "streams")
    );

    private final Policy policy;
    private final CelCompiler compiler;
    private final CelRuntime runtime;

    private PolicyEngine(Policy policy, CelCompiler compiler, CelRuntime runtime) {
        this.policy = policy;
        this.compiler = compiler;
        this.runtime = runtime;
    }

    public static PolicyEngine load(File policyFile) throws IOException {
        var policy = YAML.readValue(policyFile, Policy.class);
        validate(policy);

        var listOfDyn = ListType.create(SimpleType.DYN);
        var mapStringDyn = MapType.create(SimpleType.STRING, SimpleType.DYN);

        var compiler = CelCompilerFactory.standardCelCompilerBuilder()
            .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
            .addVar("brokers", listOfDyn)
            .addVar("topics", listOfDyn)
            .addVar("topic_meta", mapStringDyn)
            .addVar("acls", listOfDyn)
            .addVar("acl_meta", mapStringDyn)
            .addVar("quotas", listOfDyn)
            .addVar("quota_meta", mapStringDyn)
            .addVar("cluster", mapStringDyn)
            .addVar("jmx", mapStringDyn)
            .addVar("fs", mapStringDyn)
            .addVar("tls", mapStringDyn)
            .addVar("process", mapStringDyn)
            .addVar("connect", mapStringDyn)
            .addVar("schemaregistry", mapStringDyn)
            .addVar("restproxy", mapStringDyn)
            .addVar("docs", mapStringDyn)
            .addVar("alerts", mapStringDyn)
            .addVar("siem", mapStringDyn)
            .addVar("zk", mapStringDyn)
            .addVar("consumer_jmx", mapStringDyn)
            .addVar("kms", mapStringDyn)
            .addVar("cc", mapStringDyn)
            .addVar("aws", mapStringDyn)
            .addVar("cis", mapStringDyn)
            .addVar("aiven", mapStringDyn)
            .addVar("rpcloud", mapStringDyn)
            .addVar("azure", mapStringDyn)
            .addVar("k8s", mapStringDyn)
            .addVar("gcp", mapStringDyn)
            .addVar("streams", mapStringDyn)
            .build();

        var runtime = CelRuntimeFactory.standardCelRuntimeBuilder().build();

        return new PolicyEngine(policy, compiler, runtime);
    }

    /** Reject placeholder controls. Every control must declare a real check. */
    private static void validate(Policy policy) {
        var problems = new ArrayList<String>();
        for (var c : policy.controls()) {
            if (isPlaceholder(c)) {
                problems.add(c.id() + ": condition is missing or 'true' with no "
                    + "covered_by_kafka_flavor — placeholder controls silently pass "
                    + "and are not allowed");
            }
        }
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Invalid policy: " + String.join("; ", problems));
        }
    }

    private static boolean isPlaceholder(Control c) {
        var cond = c.condition();
        var hasRealCondition = cond != null && !cond.isBlank() && !"true".equals(cond.trim());
        if (hasRealCondition) {
            return false;
        }
        var covered = c.coveredByKafkaFlavor();
        return covered == null || covered.isEmpty();
    }

    /**
     * Run every control against the collected data.
     *
     * @param availableCollectors collectors that successfully ran (used to gate {@code requires})
     */
    public ScanResult evaluate(
        Map<String, Object> collectedData,
        String clusterName,
        String kafkaFlavor,
        String kafkaFlavorSource,
        Set<String> availableCollectors
    ) {
        var activation = new HashMap<String, Object>();
        activation.put("jmx", collectedData.getOrDefault("jmx", Map.of()));
        activation.put("fs", collectedData.getOrDefault("fs", Map.of()));
        activation.put("tls", collectedData.getOrDefault("tls", Map.of()));
        activation.put("process", collectedData.getOrDefault("process", Map.of()));
        activation.put("connect", collectedData.getOrDefault("connect", Map.of()));
        activation.put("schemaregistry", collectedData.getOrDefault("schemaregistry", Map.of()));
        activation.put("restproxy", collectedData.getOrDefault("restproxy", Map.of()));
        activation.put("docs", collectedData.getOrDefault("docs", Map.of()));
        activation.put("alerts", collectedData.getOrDefault("alerts", Map.of()));
        activation.put("siem", collectedData.getOrDefault("siem", Map.of()));
        activation.put("zk", collectedData.getOrDefault("zk", Map.of()));
        activation.put("consumer_jmx", collectedData.getOrDefault("consumer_jmx", Map.of()));
        activation.put("kms", collectedData.getOrDefault("kms", Map.of()));
        activation.put("cc", collectedData.getOrDefault("cc", Map.of()));
        activation.put("aws", collectedData.getOrDefault("aws", Map.of()));
        activation.put("cis", collectedData.getOrDefault("cis", Map.of()));
        activation.put("aiven", collectedData.getOrDefault("aiven", Map.of()));
        activation.put("rpcloud", collectedData.getOrDefault("rpcloud", Map.of()));
        activation.put("azure", collectedData.getOrDefault("azure", Map.of()));
        activation.put("k8s", collectedData.getOrDefault("k8s", Map.of()));
        activation.put("gcp", collectedData.getOrDefault("gcp", Map.of()));
        activation.put("streams", collectedData.getOrDefault("streams", Map.of()));
        if (availableCollectors.contains("adminclient")) {
            activation.put("brokers", collectedData.getOrDefault("broker", List.of()));
            activation.put("topics", collectedData.getOrDefault("topic", List.of()));
            activation.put("acls", collectedData.getOrDefault("acl", List.of()));
            activation.put("acl_meta", collectedData.getOrDefault("acl_metadata", Map.of()));
            activation.put("topic_meta", collectedData.getOrDefault("topic_metadata", Map.of()));
            activation.put("quotas", collectedData.getOrDefault("quota", List.of()));
            activation.put("quota_meta", collectedData.getOrDefault("quota_metadata", Map.of()));
            activation.put("cluster", collectedData.getOrDefault("kraft", Map.of()));
        }

        List<Finding> findings = new ArrayList<>();
        List<Finding> controlResults = new ArrayList<>();
        int passCount = 0;
        int failCount = 0;
        int naCount = 0;
        int kafkaFlavorCoveredCount = 0;
        int errorCount = 0;
        int score = 100;
        var collectorsUnavailable = new java.util.LinkedHashSet<String>();

        for (var control : policy.controls()) {
            var resolution = resolve(control, collectedData, activation, kafkaFlavor,
                kafkaFlavorSource, availableCollectors,
                collectorsUnavailable);
            var status = resolution.status();
            var controlResult = buildFinding(control, status, resolution.evidence());
            controlResults.add(controlResult);

            switch (status) {
                case pass -> passCount++;
                case covered_by_flavor -> {
                    passCount++;
                    kafkaFlavorCoveredCount++;
                }
                case fail -> {
                    failCount++;
                    score = Math.max(0, score - weightFor(control));
                    findings.add(controlResult);
                }
                case na -> {
                    naCount++;
                    findings.add(controlResult);
                }
                case error -> {
                    errorCount++;
                    findings.add(controlResult);
                }
                default -> { /* unreachable */ }
            }
        }

        int evaluated = passCount + failCount;
        double passRate = evaluated > 0 ? (double) passCount / evaluated * 100.0 : 100.0;

        int brokerCount = 0;
        int topicCount = 0;
        if (collectedData.get("broker") instanceof List<?> bl) {
            brokerCount = bl.size();
        }
        if (collectedData.get("topic") instanceof List<?> tl) {
            topicCount = tl.size();
        }
        var clusterMode = "unknown";
        if (collectedData.get("kraft") instanceof Map<?, ?> clusterMap
            && clusterMap.get("mode") instanceof String mode
            && !mode.isBlank()) {
            clusterMode = mode;
        }

        return new ScanResult(
            clusterName, "prod", Instant.now().toString(),
            score, passCount, failCount, naCount,
            kafkaFlavorCoveredCount, errorCount,
            passRate,
            new ArrayList<>(availableCollectors), new ArrayList<>(collectorsUnavailable),
            controlResults,
            findings,
            new ClusterInfo(clusterName, brokerCount, topicCount, 0, clusterMode,
                kafkaFlavor, kafkaFlavorSource)
        );
    }

    private record Resolution(Status status, Map<String, Object> evidence) { }

    private Resolution resolve(
        Control control,
        Map<String, Object> collectedData,
        Map<String, Object> activation,
        String kafkaFlavor,
        String kafkaFlavorSource,
        Set<String> availableCollectors,
        Set<String> collectorsUnavailable
    ) {
        var evidence = baseEvidence(control, kafkaFlavor, kafkaFlavorSource, availableCollectors);
        var coveredBy = control.coveredByKafkaFlavor();
        if (coveredBy != null && coveredBy.contains(kafkaFlavor)) {
            var coverage = flavorCoverageEvidence(kafkaFlavor, kafkaFlavorSource, collectedData);
            evidence.put("flavor_coverage", coverage);
            if (Boolean.TRUE.equals(coverage.get("verified"))) {
                evidence.put("reason", "managed service coverage verified");
                return new Resolution(Status.covered_by_flavor, evidence);
            }
            evidence.put("reason", "managed service coverage is not verified by collector evidence");
        }

        var requires = control.requires();
        if (requires != null && !requires.isEmpty()) {
            for (var req : requires) {
                if (!availableCollectors.contains(req)) {
                    collectorsUnavailable.add(req);
                    evidence.put("reason", "required collector not available");
                    evidence.put("missing_collectors", List.of(req));
                    return new Resolution(Status.na, evidence);
                }
            }
        }

        // Mode-conditional requires: only enforce the branch that matches
        // the detected cluster.mode. Lets ZK-004 demand the `zk` collector
        // for ZK clusters without dragging it onto KRaft scans.
        var perMode = control.requiresPerMode();
        if (perMode != null && !perMode.isEmpty()) {
            var clusterMap = activation.get("cluster");
            String mode = "unknown";
            if (clusterMap instanceof Map<?, ?> m) {
                var v = m.get("mode");
                if (v instanceof String s) {
                    mode = s;
                }
            }
            var modeRequires = perMode.get(mode);
            if (modeRequires != null) {
                for (var req : modeRequires) {
                    if (!availableCollectors.contains(req)) {
                        collectorsUnavailable.add(req);
                        evidence.put("reason", "mode-required collector not available");
                        evidence.put("cluster_mode", mode);
                        evidence.put("missing_collectors", List.of(req));
                        return new Resolution(Status.na, evidence);
                    }
                }
            }
        }

        var condition = control.condition();
        if (condition == null || condition.isBlank()) {
            evidence.put("reason", "condition missing");
            return new Resolution(Status.error, evidence);
        }
        dev.cel.common.CelAbstractSyntaxTree ast;
        try {
            ast = compiler.compile(condition).getAst();
        } catch (Exception e) {
            System.err.printf("CEL compile failed %s: %s%n", control.id(), e.getMessage());
            evidence.put("reason", "condition compile error");
            evidence.put("error", e.getMessage());
            return new Resolution(Status.error, evidence);
        }

        var policyRefs = policyReferences(ast.getExpr());
        evidence.put("referenced_vars", new ArrayList<>(policyRefs));
        evidence.put("observed", observedForReferences(policyRefs, activation));

        var adminClientRefs = adminClientReferences(ast.getExpr());
        if (!adminClientRefs.isEmpty()) {
            if (!availableCollectors.contains("adminclient")) {
                collectorsUnavailable.add("adminclient");
                evidence.put("reason", "required collector not available");
                evidence.put("missing_collectors", List.of("adminclient"));
                return new Resolution(Status.na, evidence);
            }
            var missingSlices = missingAdminClientSlices(adminClientRefs, collectedData);
            if (!missingSlices.isEmpty()) {
                collectorsUnavailable.addAll(missingSlices);
                evidence.put("reason", "required adminclient data slice not collected");
                evidence.put("missing_data_slices", new ArrayList<>(missingSlices));
                return new Resolution(Status.na, evidence);
            }
        }

        try {
            var program = runtime.createProgram(ast);
            var result = program.eval(activation);
            var passed = Boolean.TRUE.equals(result);
            evidence.put("reason", passed ? "condition evaluated true" : "condition evaluated false");
            evidence.put("evaluation_result", result);
            return new Resolution(passed ? Status.pass : Status.fail, evidence);
        } catch (Exception e) {
            System.err.printf("CEL eval failed %s: %s%n", control.id(), e.getMessage());
            evidence.put("reason", "condition evaluation error");
            evidence.put("error", e.getMessage());
            return new Resolution(Status.error, evidence);
        }
    }

    private static Finding buildFinding(
        Control control, Status status, Map<String, Object> evidence
    ) {
        return new Finding(
            control.id(), control.severity(), control.category(), status,
            control.title(), control.message(), control.remediation(),
            evidence, control.compliance()
        );
    }

    private static Map<String, Object> baseEvidence(
        Control control,
        String kafkaFlavor,
        String kafkaFlavorSource,
        Set<String> availableCollectors
    ) {
        var evidence = new java.util.LinkedHashMap<String, Object>();
        evidence.put("control_id", control.id());
        evidence.put("condition", control.condition() == null ? "" : control.condition());
        evidence.put("requires", control.requires());
        evidence.put("requires_per_mode", control.requiresPerMode());
        evidence.put("kafka_flavor", kafkaFlavor);
        evidence.put("kafka_flavor_source", kafkaFlavorSource);
        evidence.put("collectors_available", new ArrayList<>(availableCollectors));
        return evidence;
    }

    private static Map<String, Object> flavorCoverageEvidence(
        String kafkaFlavor,
        String kafkaFlavorSource,
        Map<String, Object> collectedData
    ) {
        var out = new java.util.LinkedHashMap<String, Object>();
        out.put("flavor", kafkaFlavor);
        out.put("source", kafkaFlavorSource);
        if ("override".equals(kafkaFlavorSource)) {
            out.put("verified", false);
            out.put("reason", "manual flavor override is not accepted as managed-service proof");
            return out;
        }
        var verified = switch (kafkaFlavor) {
            case "confluent-cloud" -> verifiedBool(collectedData, "cc", "cluster_authenticated")
                && hasNonBlank(collectedData, "cc", "cluster_id");
            case "aws-msk" -> verifiedBool(collectedData, "aws", "sdk_available")
                && hasNonBlank(collectedData, "aws", "cluster_arn");
            case "aiven" -> verifiedBool(collectedData, "aiven", "service_present");
            case "redpanda-cloud" -> verifiedBool(collectedData, "rpcloud", "cluster_present");
            case "azure-eventhubs" -> verifiedBool(collectedData, "azure", "namespace_present");
            default -> false;
        };
        out.put("verified", verified);
        out.put("reason", verified
            ? "vendor collector evidence present"
            : "vendor collector evidence missing or incomplete");
        return out;
    }

    private static boolean verifiedBool(Map<String, Object> collectedData, String namespace, String key) {
        return collectedData.get(namespace) instanceof Map<?, ?> m
            && Boolean.TRUE.equals(m.get(key));
    }

    private static boolean hasNonBlank(Map<String, Object> collectedData, String namespace, String key) {
        return collectedData.get(namespace) instanceof Map<?, ?> m
            && m.get(key) instanceof String s
            && !s.isBlank();
    }

    /** Backwards-compatible shim used by tests; treats the cluster as vanilla. */
    public ScanResult evaluate(Map<String, Object> collectedData, String clusterName) {
        return evaluate(collectedData, clusterName, "vanilla", "default",
            Set.of("adminclient"));
    }

    public Policy policy() {
        return policy;
    }

    private int weightFor(Control control) {
        var fallback = WEIGHTS.getOrDefault(control.severity().name(), 5);
        var scoring = policy.scoring();
        if (scoring == null || scoring.weights() == null) {
            return fallback;
        }
        return scoring.weights().getOrDefault(control.severity().name(), fallback);
    }

    private static Set<String> adminClientReferences(dev.cel.common.ast.CelExpr expr) {
        var refs = new java.util.LinkedHashSet<String>();
        collectAdminClientReferences(expr, refs);
        return refs;
    }

    private static Set<String> policyReferences(dev.cel.common.ast.CelExpr expr) {
        var refs = new java.util.LinkedHashSet<String>();
        collectPolicyReferences(expr, refs);
        return refs;
    }

    private static void collectPolicyReferences(
        dev.cel.common.ast.CelExpr expr,
        Set<String> refs
    ) {
        switch (expr.getKind()) {
            case IDENT -> {
                var name = expr.ident().name();
                if (POLICY_VAR_TO_DATA_KEY.containsKey(name)) {
                    refs.add(name);
                }
            }
            case SELECT -> collectPolicyReferences(expr.select().operand(), refs);
            case CALL -> {
                var call = expr.call();
                call.target().ifPresent(target -> collectPolicyReferences(target, refs));
                call.args().forEach(arg -> collectPolicyReferences(arg, refs));
            }
            case LIST -> expr.list().elements()
                .forEach(element -> collectPolicyReferences(element, refs));
            case STRUCT -> expr.struct().entries()
                .forEach(entry -> collectPolicyReferences(entry.value(), refs));
            case MAP -> expr.map().entries().forEach(entry -> {
                collectPolicyReferences(entry.key(), refs);
                collectPolicyReferences(entry.value(), refs);
            });
            case COMPREHENSION -> {
                var c = expr.comprehension();
                collectPolicyReferences(c.iterRange(), refs);
                collectPolicyReferences(c.accuInit(), refs);
                collectPolicyReferences(c.loopCondition(), refs);
                collectPolicyReferences(c.loopStep(), refs);
                collectPolicyReferences(c.result(), refs);
            }
            case CONSTANT, NOT_SET -> { }
            default -> { }
        }
    }

    private static void collectAdminClientReferences(
        dev.cel.common.ast.CelExpr expr,
        Set<String> refs
    ) {
        switch (expr.getKind()) {
            case IDENT -> {
                var name = expr.ident().name();
                if (ADMIN_CLIENT_VARS.contains(name)) {
                    refs.add(name);
                }
            }
            case SELECT -> collectAdminClientReferences(expr.select().operand(), refs);
            case CALL -> {
                var call = expr.call();
                call.target().ifPresent(target -> collectAdminClientReferences(target, refs));
                call.args().forEach(arg -> collectAdminClientReferences(arg, refs));
            }
            case LIST -> expr.list().elements()
                .forEach(element -> collectAdminClientReferences(element, refs));
            case STRUCT -> expr.struct().entries()
                .forEach(entry -> collectAdminClientReferences(entry.value(), refs));
            case MAP -> expr.map().entries().forEach(entry -> {
                collectAdminClientReferences(entry.key(), refs);
                collectAdminClientReferences(entry.value(), refs);
            });
            case COMPREHENSION -> {
                var c = expr.comprehension();
                collectAdminClientReferences(c.iterRange(), refs);
                collectAdminClientReferences(c.accuInit(), refs);
                collectAdminClientReferences(c.loopCondition(), refs);
                collectAdminClientReferences(c.loopStep(), refs);
                collectAdminClientReferences(c.result(), refs);
            }
            case CONSTANT, NOT_SET -> { }
            default -> { }
        }
    }

    private static Set<String> missingAdminClientSlices(
        Set<String> refs,
        Map<String, Object> collectedData
    ) {
        var missing = new java.util.LinkedHashSet<String>();
        for (var ref : refs) {
            var dataKey = ADMIN_CLIENT_VAR_TO_DATA_KEY.get(ref);
            if (dataKey == null || collectedData.containsKey(dataKey)) {
                continue;
            }
            missing.add("adminclient:" + dataKey);
        }
        return missing;
    }

    private static Map<String, Object> observedForReferences(
        Set<String> refs,
        Map<String, Object> activation
    ) {
        var out = new java.util.LinkedHashMap<String, Object>();
        for (var ref : refs) {
            if (activation.containsKey(ref)) {
                out.put(ref, sanitizeEvidence(activation.get(ref)));
            } else {
                out.put(ref, "<absent>");
            }
        }
        return out;
    }

    private static Object sanitizeEvidence(@Nullable Object value) {
        return sanitizeEvidence(value, 0);
    }

    private static Object sanitizeEvidence(@Nullable Object value, int depth) {
        if (value == null) {
            return "<null>";
        }
        if (depth > 4) {
            return "<truncated>";
        }
        if (value instanceof Map<?, ?> map) {
            var out = new java.util.LinkedHashMap<String, Object>();
            int count = 0;
            for (var entry : map.entrySet()) {
                if (count++ >= 80) {
                    out.put("_truncated", true);
                    break;
                }
                var key = String.valueOf(entry.getKey());
                out.put(key, isSensitiveKey(key)
                    ? "<redacted>"
                    : sanitizeEvidence(entry.getValue(), depth + 1));
            }
            return out;
        }
        if (value instanceof List<?> list) {
            var out = new ArrayList<Object>();
            int limit = Math.min(list.size(), 50);
            for (int i = 0; i < limit; i++) {
                out.add(sanitizeEvidence(list.get(i), depth + 1));
            }
            if (list.size() > limit) {
                out.add("<truncated:" + (list.size() - limit) + " more>");
            }
            return out;
        }
        if (value instanceof String s) {
            return s.length() <= 4096 ? s : s.substring(0, 4096) + "...";
        }
        return value;
    }

    private static boolean isSensitiveKey(String key) {
        var lower = key.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("password")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("credential")
            || lower.contains("authorization")
            || lower.contains("auth_header")
            || lower.contains("api_key")
            || lower.contains("api-key")
            || lower.contains("private_key")
            || lower.contains("private-key")
            || lower.contains("sasl.jaas.config")
            || lower.endsWith("jaas.config");
    }
}
