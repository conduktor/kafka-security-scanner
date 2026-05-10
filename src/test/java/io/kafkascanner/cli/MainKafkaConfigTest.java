package io.kafkascanner.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainKafkaConfigTest {

    @Test
    void loadsProductionKafkaClientProperties(@TempDir Path tmp) throws Exception {
        var clientProperties = tmp.resolve("client.properties");
        Files.writeString(clientProperties, """
            security.protocol=SASL_SSL
            ssl.truststore.location=/etc/kafka/client.truststore.p12
            ssl.truststore.type=PKCS12
            sasl.mechanism=OAUTHBEARER
            sasl.login.callback.handler.class=com.example.OAuthHandler
            """);

        var props = new Properties();
        Main.loadKafkaClientConfig(props, clientProperties.toString());

        assertThat(props.getProperty("security.protocol")).isEqualTo("SASL_SSL");
        assertThat(props.getProperty("ssl.truststore.location"))
            .isEqualTo("/etc/kafka/client.truststore.p12");
        assertThat(props.getProperty("sasl.login.callback.handler.class"))
            .isEqualTo("com.example.OAuthHandler");
    }

    @Test
    void escapesGeneratedJaasValues() {
        assertThat(Main.jaasEscape("user\"name\\prod")).isEqualTo("user\\\"name\\\\prod");
    }
}
