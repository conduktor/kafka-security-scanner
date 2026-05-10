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
import java.util.Optional;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
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
    private static final int SAN_DNS = 2;
    private static final int SAN_IP = 7;

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
        var host = stripIpv6Brackets(hostPort.substring(0, colon));
        int port;
        try {
            port = Integer.parseInt(hostPort.substring(colon + 1));
        } catch (NumberFormatException e) {
            return Map.of();
        }

        var tls = new HashMap<String, Object>();
        tls.put("host", host);
        tls.put("port", port);

        // Distinguish "endpoint is plaintext" (we should skip TLS-bound checks) from
        // "endpoint is TLS but the cert is broken" (real fail). We try a TCP connect
        // first; if the server doesn't speak TLS we mark plaintext_endpoint=true.
        tls.put("plaintext_endpoint", false);
        try {
            var ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {INSPECTING_TRUST_MANAGER}, null);
            try (SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), HANDSHAKE_TIMEOUT_MS);
                if (!isIpLiteral(host)) {
                    var params = new SSLParameters();
                    params.setServerNames(java.util.List.of(new SNIHostName(host)));
                    socket.setSSLParameters(params);
                }
                try {
                    socket.startHandshake();
                } catch (javax.net.ssl.SSLException sslEx) {
                    // Plaintext / non-SSL listener returns garbage during handshake.
                    var msg = String.valueOf(sslEx.getMessage()).toLowerCase(Locale.ROOT);
                    if (msg.contains("plaintext") || msg.contains("unrecognized")
                        || msg.contains("not an ssl") || msg.contains("end of file")) {
                        tls.put("handshake_ok", false);
                        tls.put("plaintext_endpoint", true);
                        tls.put("error", sslEx.getClass().getSimpleName() + ": " + sslEx.getMessage());
                        return Map.of("tls", tls);
                    }
                    throw sslEx;
                }

                var session = socket.getSession();
                tls.put("handshake_ok", true);
                tls.put("protocol", session.getProtocol());
                tls.put("cipher_suite", session.getCipherSuite());

                var peerCerts = session.getPeerCertificates();
                var chain = new ArrayList<Map<String, Object>>();
                X509Certificate leafCert = null;
                for (var c : peerCerts) {
                    if (c instanceof X509Certificate x) {
                        if (leafCert == null) {
                            leafCert = x;
                        }
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
                    tls.put("hostname_match", leafCert != null && hostnameMatches(leafCert, host));
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
        var dnsSans = new ArrayList<String>();
        var ipSans = new ArrayList<String>();
        try {
            var altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (var entry : altNames) {
                    if (entry.size() >= 2 && entry.get(0) instanceof Integer type
                        && entry.get(1) instanceof String s) {
                        if (type == SAN_DNS) {
                            dnsSans.add(s);
                            sans.add(s);
                        } else if (type == SAN_IP) {
                            ipSans.add(s);
                            sans.add(s);
                        }
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            // SANs unparseable; leave empty
        }
        info.put("subject_alternative_names", sans);
        info.put("dns_subject_alternative_names", dnsSans);
        info.put("ip_subject_alternative_names", ipSans);
        return info;
    }

    static boolean dnsNameMatches(String pattern, String host) {
        var normalizedPattern = normalizeDnsName(pattern);
        var normalizedHost = normalizeDnsName(host);
        if (normalizedPattern.isBlank() || normalizedHost.isBlank()) {
            return false;
        }
        if (!normalizedPattern.startsWith("*.")) {
            return normalizedPattern.equals(normalizedHost);
        }
        var suffix = normalizedPattern.substring(1);
        if (!normalizedHost.endsWith(suffix)) {
            return false;
        }
        var prefix = normalizedHost.substring(0, normalizedHost.length() - suffix.length());
        return !prefix.isBlank() && prefix.indexOf('.') < 0;
    }

    static boolean hostnameMatches(X509Certificate cert, String host) {
        var normalizedHost = stripIpv6Brackets(host);
        var dnsSans = new ArrayList<String>();
        var ipSans = new ArrayList<String>();
        try {
            var altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (var entry : altNames) {
                    if (entry.size() >= 2 && entry.get(0) instanceof Integer type
                        && entry.get(1) instanceof String s) {
                        if (type == SAN_DNS) {
                            dnsSans.add(s);
                        } else if (type == SAN_IP) {
                            ipSans.add(s);
                        }
                    }
                }
            }
        } catch (java.security.cert.CertificateParsingException e) {
            return false;
        }

        if (isIpLiteral(normalizedHost)) {
            for (var ip : ipSans) {
                if (ip.equalsIgnoreCase(normalizedHost)) {
                    return true;
                }
            }
            return false;
        }

        if (!dnsSans.isEmpty()) {
            for (var dnsName : dnsSans) {
                if (dnsNameMatches(dnsName, normalizedHost)) {
                    return true;
                }
            }
            return false;
        }

        return commonName(cert)
            .map(cn -> dnsNameMatches(cn, normalizedHost))
            .orElse(false);
    }

    private static Optional<String> commonName(X509Certificate cert) {
        try {
            var ldapName = new LdapName(cert.getSubjectX500Principal().getName());
            for (var rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return Optional.of(String.valueOf(rdn.getValue()));
                }
            }
        } catch (InvalidNameException e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    private static boolean isIpLiteral(String host) {
        var normalizedHost = stripIpv6Brackets(host);
        return isIpv4Literal(normalizedHost) || normalizedHost.contains(":");
    }

    private static boolean isIpv4Literal(String host) {
        var parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (var part : parts) {
            if (part.isBlank() || part.length() > 3) {
                return false;
            }
            for (var i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    private static String normalizeDnsName(String value) {
        var normalized = stripIpv6Brackets(value).toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".")) {
            return normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private static String stripIpv6Brackets(String value) {
        if (value.length() >= 2 && value.charAt(0) == '[' && value.charAt(value.length() - 1) == ']') {
            return value.substring(1, value.length() - 1);
        }
        return value;
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
