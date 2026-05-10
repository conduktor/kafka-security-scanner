package io.kafkascanner.collectors;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"unchecked", "NullAway"})
class EcosystemCollectorAuditTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void connectUnauthorizedIsUnknownNotEmptyEvidence() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> respond(exchange, 401, "{}"));
        server.start();

        var ctx = CollectorTestContexts.ecosystem(baseUrl(), null, false);
        var connect = (Map<?, ?>) new ConnectCollector().collect(ctx).get("connect");

        assertThat(connect.get("reachable")).isEqualTo(true);
        assertThat(connect.get("requires_auth")).isEqualTo(true);
        assertThat(connect.get("connectors_enumerated")).isEqualTo(false);
        assertThat(connect.get("connector_count_unknown")).isEqualTo(true);
        assertThat(connect.get("connector_count")).isEqualTo(0L);
    }

    @Test
    void schemaRegistryDoesNotPostUnlessActiveProbesAreAllowed() throws IOException {
        var posts = new AtomicInteger();
        startSchemaRegistryFixture(posts);

        var ctx = CollectorTestContexts.ecosystem(null, baseUrl(), false);
        var sr = (Map<?, ?>) new SchemaRegistryCollector().collect(ctx).get("schemaregistry");

        assertThat(posts.get()).isZero();
        assertThat(sr.get("subjects_enumerated")).isEqualTo(true);
        assertThat(sr.get("write_probe_performed")).isEqualTo(false);
        assertThat(sr.get("write_probe_mode")).isEqualTo("disabled_non_mutating_default");
        assertThat(sr.get("all_subjects_require_auth")).isEqualTo(false);
        var details = (java.util.List<Map<String, Object>>) sr.get("subject_details");
        assertThat(details).singleElement()
            .extracting(d -> d.get("write_status"))
            .isEqualTo("not_probed");
    }

    @Test
    void schemaRegistryActiveProbeRequiresExplicitOptIn() throws IOException {
        var posts = new AtomicInteger();
        startSchemaRegistryFixture(posts);

        var ctx = CollectorTestContexts.ecosystem(null, baseUrl(), true);
        var sr = (Map<?, ?>) new SchemaRegistryCollector().collect(ctx).get("schemaregistry");

        assertThat(posts.get()).isEqualTo(1);
        assertThat(sr.get("write_probe_performed")).isEqualTo(true);
        assertThat(sr.get("write_probe_mode")).isEqualTo("active_opt_in");
        assertThat(sr.get("all_subjects_require_auth")).isEqualTo(true);
        assertThat(sr.get("write_anonymous_allowed")).isEqualTo(false);
    }

    private void startSchemaRegistryFixture(AtomicInteger posts) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            var path = exchange.getRequestURI().getPath();
            var method = exchange.getRequestMethod();
            if ("GET".equals(method) && "/subjects".equals(path)) {
                respond(exchange, 200, "[\"customer-value\"]");
            } else if ("GET".equals(method) && "/config".equals(path)) {
                respond(exchange, 200, "{\"compatibilityLevel\":\"BACKWARD\"}");
            } else if ("GET".equals(method)
                && "/subjects/customer-value/versions/latest".equals(path)) {
                respond(exchange, 200, "{\"schema\":\"{\\\"type\\\":\\\"record\\\"}\"}");
            } else if ("POST".equals(method)
                && "/subjects/customer-value/versions".equals(path)) {
                posts.incrementAndGet();
                respond(exchange, 401, "{}");
            } else {
                respond(exchange, 404, "{}");
            }
        });
        server.start();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
