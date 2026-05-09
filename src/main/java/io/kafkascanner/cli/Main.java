package io.kafkascanner.cli;

import static io.kafkascanner.model.ScanModels.ScanResult;
import static io.kafkascanner.model.ScanModels.Severity;

import io.kafkascanner.collectors.AdminClientCollector;
import io.kafkascanner.collectors.Collector;
import io.kafkascanner.collectors.CollectorContext;
import io.kafkascanner.collectors.CollectorRunner;
import io.kafkascanner.flavor.FlavorDetector;
import io.kafkascanner.policy.PolicyEngine;
import io.kafkascanner.reports.Reporters;
import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Picocli entrypoint. Exit codes: 0 clean, 1 findings &gt;= --fail-on, 2 scan error.
 */
@Command(
    name = "kafka-security-scanner",
    mixinStandardHelpOptions = true,
    version = "1.0.0",
    description = "Scan Apache Kafka clusters for security misconfigurations."
)
@SuppressWarnings({"NullAway", "UnusedVariable"})
public final class Main implements Runnable {

    private static final int EXIT_OK = 0;
    private static final int EXIT_FINDINGS = 1;
    private static final int EXIT_ERROR = 2;

    @Option(names = {"-b", "--bootstrap"}, required = true,
            description = "Kafka bootstrap servers (comma-separated)")
    private String bootstrap;

    @Option(names = {"-p", "--policy"}, defaultValue = "enterprise",
            description = "Policy: enterprise, community, or path to YAML")
    private String policyName;

    @Option(names = {"-f", "--format"}, defaultValue = "terminal,json",
            description = "Report formats (comma-separated): json,html,csv,sarif,pdf,terminal")
    private String format;

    @Option(names = {"-o", "--out"}, defaultValue = "./reports",
            description = "Output directory for reports")
    private String outDir;

    @Option(names = {"--timeout"}, defaultValue = "60",
            description = "Scan timeout in seconds")
    private int timeout;

    @Option(names = {"--fail-on"}, defaultValue = "high",
            description = "Severity threshold that triggers exit code 1: critical|high|medium|low|info|none")
    private String failOn;

    @Option(names = {"--cluster-name"}, defaultValue = "",
            description = "Override cluster display name (defaults to bootstrap)")
    private String clusterName;

    @Option(names = {"--security-protocol"}, defaultValue = "",
            description = "PLAINTEXT|SASL_PLAINTEXT|SSL|SASL_SSL (default: PLAINTEXT)")
    private String securityProtocol;

    @Option(names = {"--sasl-mechanism"}, defaultValue = "",
            description = "PLAIN|SCRAM-SHA-256|SCRAM-SHA-512|GSSAPI")
    private String saslMechanism;

    @Option(names = {"--sasl-username"}, defaultValue = "",
            description = "SASL username (for PLAIN/SCRAM)")
    private String saslUsername;

    @Option(names = {"--sasl-password"}, defaultValue = "",
            description = "SASL password (for PLAIN/SCRAM)")
    private String saslPassword;

    @Option(names = {"--sasl-jaas-config"}, defaultValue = "",
            description = "Raw JAAS config string; overrides --sasl-username/--sasl-password")
    private String saslJaasConfig;

    @Option(names = {"--kafka-flavor"}, defaultValue = "",
            description = "Override auto-detected Kafka flavor: confluent-cloud|aws-msk|aiven|"
                + "redpanda-cloud|azure-eventhubs|warpstream|conduktor-gateway|vanilla")
    private String kafkaFlavorOverride;

    @Option(names = {"--collectors"}, defaultValue = "adminclient",
            description = "Comma-separated collectors to enable: "
                + "adminclient,jmx,filesystem (default: adminclient)")
    private String collectorsCsv;

    @Option(names = {"--kafka-config-dir"}, defaultValue = "",
            description = "Local path to broker config directory for the filesystem collector "
                + "(usually /etc/kafka or /opt/kafka/config)")
    private String kafkaConfigDir;

    @Option(names = {"--jmx-host-port"}, defaultValue = "",
            description = "host:port of broker JMX endpoint for the jmx collector (e.g. localhost:9999)")
    private String jmxHostPort;

    @Option(names = {"--connect-url"}, defaultValue = "",
            description = "Kafka Connect REST URL for the connect collector (e.g. http://host:8083)")
    private String connectUrl;

    @Option(names = {"--schema-registry-url"}, defaultValue = "",
            description = "Schema Registry REST URL for the schemaregistry collector")
    private String schemaRegistryUrl;

    @Option(names = {"--rest-proxy-url"}, defaultValue = "",
            description = "Kafka REST Proxy URL for the restproxy collector")
    private String restProxyUrl;

    @Option(names = {"--docs-dir"}, defaultValue = "",
            description = "Directory of governance artifacts (runbooks, drill logs) for the docs collector")
    private String docsDir;

    @Option(names = {"--prometheus-url"}, defaultValue = "",
            description = "Prometheus base URL for the alerts collector (e.g. http://prom:9090)")
    private String prometheusUrl;

    @Option(names = {"--zk-admin-host-port"}, defaultValue = "",
            description = "host:port of ZooKeeper admin (4lw) endpoint for the zk collector")
    private String zkAdminHostPort;

    private static final Map<String, String> BUILTIN_POLICIES = Map.of(
        "enterprise", "policies/enterprise-default.yaml",
        "community", "policies/test-minimal-valid.yaml",
        "baseline", "policies/test-minimal-valid.yaml"
    );

    @Override
    public void run() {
        try {
            System.out.println("=== Kafka Security Scanner v1.0.0 ===");
            System.out.println("Bootstrap: " + bootstrap);
            System.out.println("Format: " + format + " | Output: " + outDir);

            var policyPath = BUILTIN_POLICIES.getOrDefault(policyName, policyName);
            var policyFile = new File(policyPath);
            if (!policyFile.exists()) {
                System.err.println("Policy file not found: " + policyPath);
                System.exit(EXIT_ERROR);
            }
            System.out.println("Policy: " + policyFile.getName());
            var engine = PolicyEngine.load(policyFile);

            var detection = FlavorDetector.detect(bootstrap, kafkaFlavorOverride);
            System.out.println("Kafka flavor: " + detection.flavor() + "  (" + detection.source() + ")");

            var props = new Properties();
            props.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrap);
            var timeoutMs = (int) Duration.ofSeconds(timeout).toMillis();
            props.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, timeoutMs);
            props.put(AdminClientConfig.DEFAULT_API_TIMEOUT_MS_CONFIG, timeoutMs);
            applySaslConfig(props);
            if (props.containsKey("security.protocol")) {
                System.out.println("Auth: " + props.getProperty("security.protocol")
                    + " / " + props.getProperty("sasl.mechanism", "n/a"));
            }

            try (var admin = AdminClient.create(props)) {
                var saslProps = new java.util.HashMap<String, String>();
                for (var name : props.stringPropertyNames()) {
                    saslProps.put(name, props.getProperty(name));
                }
                var ctx = new CollectorContext(
                    bootstrap, Duration.ofSeconds(timeout), admin,
                    kafkaConfigDir.isBlank() ? null : kafkaConfigDir,
                    jmxHostPort.isBlank() ? null : jmxHostPort,
                    connectUrl.isBlank() ? null : connectUrl,
                    schemaRegistryUrl.isBlank() ? null : schemaRegistryUrl,
                    restProxyUrl.isBlank() ? null : restProxyUrl,
                    docsDir.isBlank() ? null : docsDir,
                    prometheusUrl.isBlank() ? null : prometheusUrl,
                    zkAdminHostPort.isBlank() ? null : zkAdminHostPort,
                    java.util.Map.copyOf(saslProps), detection.flavor()
                );
                var enabled = CollectorRunner.parseNames(collectorsCsv);
                var collectors = new java.util.ArrayList<Collector>();
                if (enabled.contains("adminclient")) {
                    collectors.add(new AdminClientCollector());
                }
                if (enabled.contains("jmx")) {
                    collectors.add(new io.kafkascanner.collectors.JmxCollector());
                }
                if (enabled.contains("filesystem")) {
                    collectors.add(new io.kafkascanner.collectors.FilesystemCollector());
                }
                if (enabled.contains("tls")) {
                    collectors.add(new io.kafkascanner.collectors.TlsCollector());
                }
                if (enabled.contains("process")) {
                    collectors.add(new io.kafkascanner.collectors.ProcessCollector());
                }
                if (enabled.contains("connect")) {
                    collectors.add(new io.kafkascanner.collectors.ConnectCollector());
                }
                if (enabled.contains("schemaregistry")) {
                    collectors.add(new io.kafkascanner.collectors.SchemaRegistryCollector());
                }
                if (enabled.contains("restproxy")) {
                    collectors.add(new io.kafkascanner.collectors.RestProxyCollector());
                }
                if (enabled.contains("docs")) {
                    collectors.add(new io.kafkascanner.collectors.DocsCollector());
                }
                if (enabled.contains("alerts")) {
                    collectors.add(new io.kafkascanner.collectors.AlertRuleCollector());
                }
                if (enabled.contains("siem")) {
                    collectors.add(new io.kafkascanner.collectors.SiemCollector());
                }
                if (enabled.contains("zk")) {
                    collectors.add(new io.kafkascanner.collectors.ZkAdminCollector());
                }
                System.out.println("Collecting cluster data ("
                    + collectors.stream().map(Collector::name)
                        .collect(java.util.stream.Collectors.joining(",")) + ")...");
                var outcome = CollectorRunner.run(collectors, ctx);

                var brokerData = outcome.data().get("broker");
                if (brokerData == null
                    || (brokerData instanceof java.util.List<?> bl && bl.isEmpty())) {
                    System.err.println("Scan error: no broker data collected (cluster unreachable?)");
                    System.exit(EXIT_ERROR);
                }

                System.out.println("Evaluating " + engine.policy().controls().size() + " controls...");
                var displayName = clusterName.isBlank() ? bootstrap : clusterName;
                var result = engine.evaluate(outcome.data(), displayName,
                    detection.flavor(), detection.source(), outcome.ran());

                printTerminal(result);

                var written = Reporters.write(result, format, Path.of(outDir));
                for (var p : written) {
                    System.out.println("Wrote: " + p);
                }

                System.exit(computeExit(result));
            }
        } catch (Exception e) {
            System.err.println("Scan failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(EXIT_ERROR);
        }
    }

    private void printTerminal(ScanResult result) {
        System.out.printf(Locale.ROOT,
            "%n  Score: %d/100  |  Pass: %d  |  Fail: %d  |  Pass Rate: %.0f%%%n",
            result.score(), result.passCount(), result.failCount(), result.passRate());
        if (result.kafkaFlavorCoveredCount() > 0) {
            System.out.printf(Locale.ROOT,
                "  · %d covered by %s SLA%n",
                result.kafkaFlavorCoveredCount(), result.cluster().kafkaFlavor());
        }
        if (result.naCount() > 0) {
            System.out.printf(Locale.ROOT,
                "  · %d N/A — required collectors unavailable: %s%n",
                result.naCount(), String.join(",", result.collectorsUnavailable()));
        }
        if (result.errorCount() > 0) {
            System.out.printf(Locale.ROOT, "  · %d evaluation errors%n", result.errorCount());
        }
        if (!result.findings().isEmpty()) {
            System.out.println("\n  Top findings:");
            Reporters.sortedBySeverity(result.findings()).stream()
                .limit(5)
                .forEach(f -> {
                    var msg = f.message();
                    var trimmed = msg.length() > 80 ? msg.substring(0, 80) : msg;
                    System.out.printf(Locale.ROOT, "    %s %s: %s%n",
                        f.severity().name(), f.controlId(), trimmed);
                });
        }
    }


    private void applySaslConfig(Properties props) {
        if (!securityProtocol.isBlank()) {
            props.put("security.protocol", securityProtocol);
        }
        if (!saslMechanism.isBlank()) {
            props.put("sasl.mechanism", saslMechanism);
        }
        if (!saslJaasConfig.isBlank()) {
            props.put("sasl.jaas.config", saslJaasConfig);
        } else if (!saslUsername.isBlank()) {
            var module = saslMechanism.startsWith("SCRAM")
                ? "org.apache.kafka.common.security.scram.ScramLoginModule"
                : "org.apache.kafka.common.security.plain.PlainLoginModule";
            props.put("sasl.jaas.config",
                module + " required username=\"" + saslUsername
                    + "\" password=\"" + saslPassword + "\";");
        }
    }

    private int computeExit(ScanResult result) {
        var threshold = parseThreshold(failOn);
        if (threshold < 0) {
            return EXIT_OK;
        }
        for (var f : result.findings()) {
            if (severityOrder(f.severity()) >= threshold) {
                return EXIT_FINDINGS;
            }
        }
        return EXIT_OK;
    }

    private static int parseThreshold(String name) {
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "critical" -> 4;
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            case "info" -> 0;
            case "none", "off" -> -1;
            default -> 3;
        };
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

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }
}
