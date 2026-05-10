package io.kafkascanner.collectors;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class JmxConnectorSupportTest {

    @Test
    void timeoutMillisIsBoundedAndPositive() {
        assertThat(JmxConnectorSupport.timeoutMillis(Duration.ZERO)).isEqualTo(1);
        assertThat(JmxConnectorSupport.timeoutMillis(Duration.ofSeconds(5))).isEqualTo(5_000);
        assertThat(JmxConnectorSupport.timeoutMillis(Duration.ofDays(30))).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    void environmentIncludesSocketFactoryAndRequestTimeouts() {
        var env = JmxConnectorSupport.environment(Duration.ofSeconds(3));

        assertThat(env).containsKeys(
            "com.sun.jndi.rmi.factory.socket",
            "jmx.remote.x.request.waiting.timeout",
            "jmx.remote.x.notification.fetch.timeout");
        assertThat(env.get("jmx.remote.x.request.waiting.timeout")).isEqualTo(3_000L);
    }
}
