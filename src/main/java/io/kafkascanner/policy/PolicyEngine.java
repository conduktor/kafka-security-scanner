package io.kafkascanner.policy;

import static io.kafkascanner.model.ScanModels.ClusterInfo;
import static io.kafkascanner.model.ScanModels.Finding;
import static io.kafkascanner.model.ScanModels.Policy;
import static io.kafkascanner.model.ScanModels.ScanResult;

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

/**
 * Policy loading and evaluation using Google cel-java with comprehension macros.
 */
public final class PolicyEngine {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

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

        var listOfDyn = ListType.create(SimpleType.DYN);
        var mapStringDyn = MapType.create(SimpleType.STRING, SimpleType.DYN);

        var compiler = CelCompilerFactory.standardCelCompilerBuilder()
            .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
            .addVar("brokers", listOfDyn)
            .addVar("topics", listOfDyn)
            .addVar("acls", listOfDyn)
            .addVar("cluster", mapStringDyn)
            .build();

        var runtime = CelRuntimeFactory.standardCelRuntimeBuilder().build();

        return new PolicyEngine(policy, compiler, runtime);
    }

    @SuppressWarnings("unchecked")
    public ScanResult evaluate(Map<String, Object> collectedData, String clusterName) {
        var activation = new HashMap<String, Object>();
        activation.put("brokers", collectedData.getOrDefault("broker", List.of()));
        activation.put("topics", collectedData.getOrDefault("topic", List.of()));
        activation.put("acls", collectedData.getOrDefault("acl", List.of()));
        activation.put("cluster", collectedData.getOrDefault("kraft", Map.of()));

        List<Finding> findings = new ArrayList<>();
        int passCount = 0;
        int failCount = 0;
        int naCount = 0;
        int score = 100;

        for (var control : policy.controls()) {
            var condition = control.condition();
            if ("true".equals(condition)) {
                passCount++;
                continue;
            }

            try {
                var ast = compiler.compile(condition).getAst();
                var program = runtime.createProgram(ast);
                var result = program.eval(activation);
                boolean passed = Boolean.TRUE.equals(result);

                if (passed) {
                    passCount++;
                } else {
                    failCount++;
                    score = Math.max(0, score - WEIGHTS.getOrDefault(control.severity().name(), 5));
                    findings.add(new Finding(
                        control.id(), control.severity(), control.category(),
                        "fail", control.title(), control.message(), control.remediation(),
                        Map.of("control_id", (Object) control.id()), control.compliance()
                    ));
                }
            } catch (Exception e) {
                naCount++;
                System.err.printf("CEL eval failed %s: %s%n", control.id(), e.getMessage());
            }
        }

        int total = passCount + failCount + naCount;
        double passRate = total > 0 ? (double) passCount / (passCount + failCount) * 100.0 : 100.0;

        int brokerCount = 0;
        int topicCount = 0;
        if (collectedData.get("broker") instanceof List<?> bl) {
            brokerCount = bl.size();
        }
        if (collectedData.get("topic") instanceof List<?> tl) {
            topicCount = tl.size();
        }

        return new ScanResult(
            clusterName, "prod", Instant.now().toString(),
            score, passCount, failCount, naCount, passRate,
            findings,
            new ClusterInfo(clusterName, brokerCount, topicCount, 0, "kraft")
        );
    }

    public Policy policy() {
        return policy;
    }
}
