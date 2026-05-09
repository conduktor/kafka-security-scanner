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
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    private final Policy policy;
    private final CelCompiler compiler;
    private final CelRuntime runtime;

    private PolicyEngine(Policy policy, CelCompiler compiler, CelRuntime runtime) {
        this.policy = policy;
        this.compiler = compiler;
        this.runtime = runtime;
    }

    public static PolicyEngine load(File policyFile) throws Exception {
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
        activation.put("brokers", collectedData.getOrDefault("broker", List.of()));
        activation.put("topics", collectedData.getOrDefault("topic", List.of()));
        activation.put("acls", collectedData.getOrDefault("acl", List.of()));
        activation.put("acl_meta", collectedData.getOrDefault("acl_metadata", Map.of()));
        activation.put("topic_meta", collectedData.getOrDefault("topic_metadata", Map.of()));
        activation.put("quotas", collectedData.getOrDefault("quota", List.of()));
        activation.put("quota_meta", collectedData.getOrDefault("quota_metadata", Map.of()));
        activation.put("cluster", collectedData.getOrDefault("kraft", Map.of()));
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

        List<Finding> findings = new ArrayList<>();
        int passCount = 0;
        int failCount = 0;
        int naCount = 0;
        int kafkaFlavorCoveredCount = 0;
        int errorCount = 0;
        int score = 100;

        for (var control : policy.controls()) {
            var status = resolve(control, activation, kafkaFlavor, availableCollectors);

            switch (status) {
                case pass -> passCount++;
                case covered_by_flavor -> {
                    passCount++;
                    kafkaFlavorCoveredCount++;
                }
                case fail -> {
                    failCount++;
                    score = Math.max(0, score
                        - WEIGHTS.getOrDefault(control.severity().name(), 5));
                    findings.add(buildFinding(control, Status.fail, kafkaFlavor,
                        "control failed evaluation"));
                }
                case na -> {
                    naCount++;
                    findings.add(buildFinding(control, Status.na, kafkaFlavor,
                        "required collector not available"));
                }
                case error -> {
                    errorCount++;
                    findings.add(buildFinding(control, Status.error, kafkaFlavor,
                        "evaluation error"));
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

        var collectorsUnavailable = new ArrayList<String>();
        for (var c : policy.controls()) {
            if (c.requires() != null) {
                for (var req : c.requires()) {
                    if (!availableCollectors.contains(req) && !collectorsUnavailable.contains(req)) {
                        collectorsUnavailable.add(req);
                    }
                }
            }
        }

        return new ScanResult(
            clusterName, "prod", Instant.now().toString(),
            score, passCount, failCount, naCount,
            kafkaFlavorCoveredCount, errorCount,
            passRate,
            new ArrayList<>(availableCollectors), collectorsUnavailable,
            findings,
            new ClusterInfo(clusterName, brokerCount, topicCount, 0, "kraft",
                kafkaFlavor, kafkaFlavorSource)
        );
    }

    private Status resolve(
        Control control,
        Map<String, Object> activation,
        String kafkaFlavor,
        Set<String> availableCollectors
    ) {
        var coveredBy = control.coveredByKafkaFlavor();
        if (coveredBy != null && coveredBy.contains(kafkaFlavor)) {
            return Status.covered_by_flavor;
        }

        var requires = control.requires();
        if (requires != null && !requires.isEmpty()) {
            for (var req : requires) {
                if (!availableCollectors.contains(req)) {
                    return Status.na;
                }
            }
        }

        var condition = control.condition();
        if (condition == null || condition.isBlank()) {
            return Status.error;
        }

        try {
            var ast = compiler.compile(condition).getAst();
            var program = runtime.createProgram(ast);
            var result = program.eval(activation);
            return Boolean.TRUE.equals(result) ? Status.pass : Status.fail;
        } catch (Exception e) {
            System.err.printf("CEL eval failed %s: %s%n", control.id(), e.getMessage());
            return Status.error;
        }
    }

    private static Finding buildFinding(
        Control control, Status status, String kafkaFlavor, String reason
    ) {
        var evidence = new HashMap<String, Object>();
        evidence.put("control_id", control.id());
        evidence.put("kafka_flavor", kafkaFlavor);
        evidence.put("reason", reason);
        return new Finding(
            control.id(), control.severity(), control.category(), status,
            control.title(), control.message(), control.remediation(),
            evidence, control.compliance()
        );
    }

    /** Backwards-compatible shim used by tests; treats the cluster as vanilla. */
    public ScanResult evaluate(Map<String, Object> collectedData, String clusterName) {
        return evaluate(collectedData, clusterName, "vanilla", "default",
            Set.of("adminclient"));
    }

    public Policy policy() {
        return policy;
    }
}
