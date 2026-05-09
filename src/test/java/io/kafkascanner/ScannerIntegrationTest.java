package io.kafkascanner;

import static org.assertj.core.api.Assertions.assertThat;

import io.kafkascanner.collectors.KafkaCollectors;
import io.kafkascanner.policy.PolicyEngine;
import io.kafkascanner.reports.Reporters;
import java.io.File;
import java.nio.file.Files;
import java.util.Properties;
import org.apache.kafka.clients.admin.AdminClient;
import org.apache.kafka.clients.admin.AdminClientConfig;
import org.apache.kafka.clients.admin.NewTopic;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.kafka.KafkaContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * End-to-end test: spin up a plaintext Kafka, scan it, assert findings and reporters.
 * Plaintext Kafka must fail SEC-001 (no TLS), SEC-011 if auto.create.topics.enable=true, etc.
 *
 * <p>Skipped when SKIP_INTEGRATION_TESTS=1 (e.g. environments without Docker).
 */
@org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable(
    named = "SKIP_INTEGRATION_TESTS", matches = "1")
class ScannerIntegrationTest {

    private static KafkaContainer kafka;
    private static AdminClient admin;

    @BeforeAll
    static void setUp() throws Exception {
        kafka = new KafkaContainer(DockerImageName.parse("apache/kafka:4.0.0"));
        kafka.start();

        var props = new Properties();
        props.put(AdminClientConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers());
        props.put(AdminClientConfig.REQUEST_TIMEOUT_MS_CONFIG, 30_000);
        admin = AdminClient.create(props);

        admin.createTopics(java.util.List.of(
            new NewTopic("test-low-rf", 1, (short) 1)
        )).all().get();
    }

    @AfterAll
    static void tearDown() {
        if (admin != null) {
            admin.close();
        }
        if (kafka != null) {
            kafka.stop();
        }
    }

    @Test
    void plaintextKafkaProducesExpectedFindings() throws Exception {
        var data = KafkaCollectors.collectAll(admin, 4);
        var engine = PolicyEngine.load(new File("policies/test-minimal-valid.yaml"));
        var result = engine.evaluate(data, "it-cluster");

        assertThat(result.findings())
            .as("plaintext Kafka must report TLS finding SEC-001")
            .extracting("controlId")
            .contains("SEC-001");

        assertThat(result.findings())
            .as("low replication factor must trigger REL-004")
            .extracting("controlId")
            .contains("REL-004");

        assertThat(result.cluster().brokers())
            .as("at least one broker must be discovered")
            .isGreaterThanOrEqualTo(1);

        assertThat(result.score()).isLessThan(100);
        assertThat(result.passCount()).isGreaterThan(0);
    }

    @Test
    void allReportersProduceNonEmptyArtifacts() throws Exception {
        var data = KafkaCollectors.collectAll(admin, 4);
        var engine = PolicyEngine.load(new File("policies/test-minimal-valid.yaml"));
        var result = engine.evaluate(data, "it-cluster");

        var tmp = Files.createTempDirectory("scanner-it");
        var written = Reporters.write(result, "json,sarif,html,csv,pdf", tmp);

        assertThat(written).hasSize(5);
        for (var path : written) {
            assertThat(Files.exists(path)).isTrue();
            assertThat(Files.size(path)).isGreaterThan(50L);
        }
    }
}
