package io.kafkascanner.collectors;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TlsCollectorTest {

    @Test
    void dnsNameMatchesExactNamesCaseInsensitively() {
        assertThat(TlsCollector.dnsNameMatches("Broker.EXAMPLE.com", "broker.example.com")).isTrue();
        assertThat(TlsCollector.dnsNameMatches("broker.example.com.", "broker.example.com")).isTrue();
        assertThat(TlsCollector.dnsNameMatches("other.example.com", "broker.example.com")).isFalse();
    }

    @Test
    void dnsNameMatchesWildcardForOneLabelOnly() {
        assertThat(TlsCollector.dnsNameMatches("*.example.com", "broker.example.com")).isTrue();
        assertThat(TlsCollector.dnsNameMatches("*.example.com", "a.broker.example.com")).isFalse();
        assertThat(TlsCollector.dnsNameMatches("*.example.com", "example.com")).isFalse();
    }
}
