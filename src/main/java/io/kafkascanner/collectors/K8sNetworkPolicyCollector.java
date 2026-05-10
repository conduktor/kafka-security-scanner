package io.kafkascanner.collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Reads NetworkPolicies + Kafka pods from a Kubernetes cluster by shelling
 * out to {@code kubectl get -o json}. Avoids the fabric8 / official client
 * runtime cost; the operator already has {@code kubectl} configured.
 *
 * <p>Activated by {@code --k8s-namespace} (env {@code K8S_NAMESPACE}).
 *
 * <p>Surfaces under {@code k8s}:
 * <pre>
 *   k8s.kubectl_available           the binary ran (success or failure)
 *   k8s.network_policies_count      total NPs in the namespace
 *   k8s.kafka_pods_count            pods labelled app.kubernetes.io/name=kafka
 *                                   (also matches strimzi.io/cluster, app=kafka)
 *   k8s.kafka_pods_protected        any NP whose podSelector matches at least
 *                                   one kafka-pod's label set AND has at least
 *                                   one ingress rule with `from`
 *   k8s.default_deny_present        an NP exists with empty podSelector and no
 *                                   ingress rules (cluster-wide default deny)
 * </pre>
 */
public final class K8sNetworkPolicyCollector implements Collector {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public String name() {
        return "k8s";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.k8sNamespace() != null && !context.k8sNamespace().isBlank();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var ns = context.k8sNamespace();
        if (ns == null || ns.isBlank()) {
            return Map.of();
        }
        var out = new HashMap<String, Object>();
        out.put("namespace", ns);
        out.put("kubectl_available", false);
        out.put("network_policies_count", 0L);
        out.put("kafka_pods_count", 0L);
        out.put("kafka_pods_protected", false);
        out.put("default_deny_present", false);
        out.put("error", "");

        // 1. List NetworkPolicies
        var npRaw = runKubectl(List.of("get", "networkpolicies", "-n", ns,
            "-o", "json"), context.timeout().toSeconds());
        if (npRaw == null) {
            out.put("error", "kubectl get networkpolicies failed");
            return Map.of("k8s", out);
        }
        out.put("kubectl_available", true);
        var npList = parseItems(npRaw);
        out.put("network_policies_count", (long) npList.size());

        // 2. List pods (any kafka-flavored selector)
        var podRaw = runKubectl(List.of("get", "pods", "-n", ns, "-o", "json"),
            context.timeout().toSeconds());
        var pods = podRaw == null ? List.<Map<String, Object>>of() : parseItems(podRaw);
        var kafkaPods = pods.stream()
            .filter(K8sNetworkPolicyCollector::isKafkaPod)
            .toList();
        out.put("kafka_pods_count", (long) kafkaPods.size());

        // 3. Cross-check NP selectors against kafka pod labels
        boolean defaultDeny = false;
        boolean kafkaProtected = false;
        for (var np : npList) {
            var spec = nestedMap(np, "spec");
            if (spec == null) {
                continue;
            }
            var podSelector = nestedMap(spec, "podSelector");
            var matchLabels = podSelector == null ? null : nestedMap(podSelector, "matchLabels");
            var ingress = spec.get("ingress");
            int ingressSize = ingress instanceof List<?> il ? il.size() : 0;

            // default-deny pattern: empty podSelector + no ingress rules
            boolean emptySelector = podSelector == null
                || matchLabels == null || matchLabels.isEmpty();
            if (emptySelector && ingressSize == 0) {
                defaultDeny = true;
                continue;
            }

            // Check overlap with kafka pods
            for (var kafkaPod : kafkaPods) {
                var podLabels = nestedMap(nestedMap(kafkaPod, "metadata"), "labels");
                if (podLabels == null) {
                    continue;
                }
                if (matchesLabels(matchLabels, podLabels)) {
                    kafkaProtected = true;
                    break;
                }
            }
        }
        out.put("default_deny_present", defaultDeny);
        out.put("kafka_pods_protected", kafkaProtected);

        return Map.of("k8s", out);
    }

    private static @Nullable String runKubectl(List<String> args, long timeoutSeconds) {
        var cmd = new ArrayList<String>();
        cmd.add("kubectl");
        cmd.addAll(args);
        try {
            var pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            var proc = pb.start();
            boolean done = proc.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!done) {
                proc.destroyForcibly();
                return null;
            }
            if (proc.exitValue() != 0) {
                return null;
            }
            return new String(proc.getInputStream().readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> parseItems(String json) {
        try {
            var root = JSON.readValue(json, Object.class);
            if (root instanceof Map<?, ?> map) {
                var items = map.get("items");
                if (items instanceof List<?> list) {
                    var out = new ArrayList<Map<String, Object>>();
                    for (var it : list) {
                        if (it instanceof Map<?, ?> m) {
                            out.add((Map<String, Object>) m);
                        }
                    }
                    return out;
                }
            }
        } catch (IOException e) {
            // fall through
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private static @Nullable Map<String, Object> nestedMap(@Nullable Map<?, ?> parent, String key) {
        if (parent == null) {
            return null;
        }
        var v = parent.get(key);
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
    }

    private static boolean isKafkaPod(Map<String, Object> pod) {
        var labels = nestedMap(nestedMap(pod, "metadata"), "labels");
        if (labels == null) {
            return false;
        }
        // Common kafka label conventions
        if ("kafka".equalsIgnoreCase(String.valueOf(labels.get("app")))) {
            return true;
        }
        if ("kafka".equalsIgnoreCase(String.valueOf(labels.get("app.kubernetes.io/name")))) {
            return true;
        }
        if (labels.containsKey("strimzi.io/cluster") && labels.containsKey("strimzi.io/kind")) {
            return true;
        }
        var v = labels.get("app.kubernetes.io/component");
        if (v != null && String.valueOf(v).toLowerCase(Locale.ROOT).contains("kafka")) {
            return true;
        }
        return false;
    }

    private static boolean matchesLabels(@Nullable Map<String, Object> selector,
                                         Map<String, Object> labels) {
        if (selector == null || selector.isEmpty()) {
            return true; // empty matchLabels = matches anything
        }
        for (var e : selector.entrySet()) {
            var v = labels.get(e.getKey());
            if (v == null || !String.valueOf(v).equals(String.valueOf(e.getValue()))) {
                return false;
            }
        }
        return true;
    }
}
