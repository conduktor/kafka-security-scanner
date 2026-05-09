package io.kafkascanner.collectors;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Opens a TLS handshake to the bootstrap host:port and inspects the server
 * certificate chain, key sizes, and negotiated protocol. Populates {@code tls}
 * on the scan data so controls can verify cert expiry, key size, signature
 * algo, SAN coverage, and protocol minimums independently from what the broker
 * config field claims.
 *
 * <p>Listener selection: the collector tries {@code bootstrap} as supplied. If
 * the listener is plaintext, the handshake fails fast and the result is empty
 * but the collector is still reported as "ran" with {@code tls.handshake_ok =
 * false}. Cross-checks AdminClient's "TLS enabled" claim against reality.
 */
public final class TlsCollector implements Collector {

    private static final int HANDSHAKE_TIMEOUT_MS = 5_000;

    @Override
    public String name() {
        return "tls";
    }

    @Override
    public boolean isAvailable(CollectorContext context) {
        return context.bootstrap() != null && !context.bootstrap().isBlank();
    }

    @Override
    public Map<String, Object> collect(CollectorContext context) {
        var hostPort = context.bootstrap().split(",", 2)[0].trim();
        var colon = hostPort.lastIndexOf(':');
        if (colon <= 0) {
            return Map.of();
        }
        var host = hostPort.substring(0, colon);
        int port;
        try {
            port = Integer.parseInt(hostPort.substring(colon + 1));
        } catch (NumberFormatException e) {
            return Map.of();
        }

        var tls = new HashMap<String, Object>();
        tls.put("host", host);
        tls.put("port", port);

        try {
            var ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {INSPECTING_TRUST_MANAGER}, null);
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), HANDSHAKE_TIMEOUT_MS);
                var params = new SSLParameters();
                params.setServerNames(java.util.List.of(new SNIHostName(host)));
                socket.setSSLParameters(params);
                socket.startHandshake();

                var session = socket.getSession();
                tls.put("handshake_ok", true);
                tls.put("protocol", session.getProtocol());
                tls.put("cipher_suite", session.getCipherSuite());

                var peerCerts = session.getPeerCertificates();
                var chain = new ArrayList<Map<String, Object>>();
                for (var c : peerCerts) {
                    if (c instanceof X509Certificate x) {
                        chain.add(describe(x));
                    }
                }
                tls.put("chain", chain);

                if (!chain.isEmpty()) {
                    var leaf = chain.get(0);
                    tls.put("days_to_expiry", leaf.get("days_to_expiry"));
                    tls.put("expired", leaf.get("expired"));
                    tls.put("key_size_bits", leaf.get("key_size_bits"));
                    tls.put("signature_algorithm", leaf.get("signature_algorithm"));
                    tls.put("hostname_match", leaf.get("hostname_match_" + host.toLowerCase(Locale.ROOT)));
                }
            }
        } catch (IOException | java.security.GeneralSecurityException e) {
            tls.put("handshake_ok", false);
            tls.put("error", e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        return Map.of("tls", tls);
    }

    private static Map<String, Object> describe(X509Certificate cert) {
        var info = new HashMap<String, Object>();
        info.put("subject", cert.getSubjectX500Principal().getName());
        info.put("issuer", cert.getIssuerX500Principal().getName());
        info.put("serial", cert.getSerialNumber().toString(16));
        info.put("not_before", cert.getNotBefore().toInstant().toString());
        info.put("not_after", cert.getNotAfter().toInstant().toString());

        var daysToExpiry = ChronoUnit.DAYS.between(
            Instant.now(), cert.getNotAfter().toInstant());
        info.put("days_to_expiry", daysToExpiry);
        info.put("expired", daysToExpiry < 0);

        info.put("signature_algorithm", cert.getSigAlgName());

        var pub = cert.getPublicKey();
        if (pub instanceof java.security.interfaces.RSAPublicKey rsa) {
            info.put("key_algorithm", "RSA");
            info.put("key_size_bits", rsa.getModulus().bitLength());
        } else if (pub instanceof java.security.interfaces.ECPublicKey ec) {
            info.put("key_algorithm", "EC");
            info.put("key_size_bits", ec.getParams().getOrder().bitLength());
        } else {
            info.put("key_algorithm", pub.getAlgorithm());
            info.put("key_size_bits", -1);
        }

        var sans = new ArrayList<String>();
        try {
            var altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (var entry : altNames) {
                    if (entry.size() >= 2 && entry.get(1) instanceof String s) {
                        sans.add(s);
                        info.put("hostname_match_" + s.toLowerCase(Locale.ROOT), true);
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            // SANs unparseable; leave empty
        }
        info.put("subject_alternative_names", sans);
        return info;
    }

    /**
     * Trust manager that accepts every chain so the collector can inspect what
     * the broker actually presents (including expired or self-signed certs).
     * The collector reports the cert details to CEL; the policy decides.
     */
    private static final X509TrustManager INSPECTING_TRUST_MANAGER = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // accept anything; we're inspecting the chain
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // accept anything; we're inspecting the chain
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    @SuppressWarnings("unused")
    private static String[] safeArray(Object o) {
        if (o instanceof String[] arr) {
            return arr.clone();
        }
        if (o instanceof java.util.Collection<?> c) {
            return c.stream().map(Object::toString).toArray(String[]::new);
        }
        return new String[0];
    }

    @SuppressWarnings("unused")
    private static String join(String[] parts) {
        return String.join(",", Arrays.asList(parts));
    }
}
