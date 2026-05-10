package io.kafkascanner.collectors;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"unchecked", "NullAway"})
class KmsCollectorTest {

    @Test
    void emptySnapshotProducesEmptyKmsNamespace() {
        var enriched = KmsCollector.aggregate(Map.of());
        var kms = (Map<?, ?>) enriched.get("kms");
        assertThat(kms.get("placeholders_found")).isEqualTo(0L);
        assertThat(kms.get("has_external_provider")).isEqualTo(false);
        assertThat((List<Object>) kms.get("providers_used")).isEmpty();
        assertThat((List<Object>) kms.get("sensitive_keys_via_provider")).isEmpty();
    }

    @Test
    void detectsExternalProviderInBrokerConfig() {
        var data = Map.<String, Object>of(
            "broker", List.of(Map.of(
                "config", Map.of(
                    "config.providers", "vault",
                    "config.providers.vault.class", "io.example.VaultConfigProvider",
                    "sasl.jaas.config", "org.apache.kafka.common.security.plain.PlainLoginModule "
                        + "required username=\"admin\" password=\"${vault:secret/kafka/admin}\";",
                    "ssl.keystore.password", "${vault:secret/kafka/keystore}"
                )))
        );
        var kms = (Map<?, ?>) KmsCollector.aggregate(data).get("kms");
        assertThat(kms.get("placeholders_found")).isEqualTo(2L);
        assertThat(kms.get("has_external_provider")).isEqualTo(true);
        assertThat((List<Object>) kms.get("providers_used")).containsExactly("vault");
        assertThat((List<Object>) kms.get("sensitive_keys_via_provider"))
            .containsExactlyInAnyOrder("sasl.jaas.config", "ssl.keystore.password");
        assertThat(kms.get("config_providers_declared")).isEqualTo("vault");
    }

    @Test
    void treatsFileAndEnvProvidersAsNonExternal() {
        var data = Map.<String, Object>of(
            "broker", List.of(Map.of(
                "config", Map.of(
                    "config.providers", "file,env",
                    "ssl.keystore.password", "${file:/etc/kafka/secrets:keystore}",
                    "ssl.key.password", "${env:KEY_PASSWORD}"
                )))
        );
        var kms = (Map<?, ?>) KmsCollector.aggregate(data).get("kms");
        assertThat(kms.get("placeholders_found")).isEqualTo(2L);
        assertThat(kms.get("has_external_provider")).isEqualTo(false);
        assertThat((List<Object>) kms.get("providers_used")).containsExactlyInAnyOrder("file", "env");
    }

    @Test
    void scansFilesystemServerProperties() {
        var data = Map.<String, Object>of(
            "fs", Map.of(
                "server_properties", Map.of(
                    "ssl.key.password", "${aws:kafka/ssl-key}"
                ))
        );
        var kms = (Map<?, ?>) KmsCollector.aggregate(data).get("kms");
        assertThat(kms.get("placeholders_found")).isEqualTo(1L);
        assertThat(kms.get("has_external_provider")).isEqualTo(true);
        assertThat((List<Object>) kms.get("sensitive_keys_via_provider")).contains("ssl.key.password");
    }

    @Test
    void scansConnectConnectorConfigs() {
        var data = Map.<String, Object>of(
            "connect", Map.of(
                "connector_configs", List.of(Map.of(
                    "name", "demo",
                    "config", Map.of(
                        "consumer.sasl.jaas.config", "${vault:secrets/kafka/consumer-creds}"
                    ))))
        );
        var kms = (Map<?, ?>) KmsCollector.aggregate(data).get("kms");
        assertThat(kms.get("placeholders_found")).isEqualTo(1L);
        assertThat((List<Object>) kms.get("providers_used")).contains("vault");
        assertThat((List<Object>) kms.get("sensitive_keys_via_provider"))
            .contains("consumer.sasl.jaas.config");
    }
}
