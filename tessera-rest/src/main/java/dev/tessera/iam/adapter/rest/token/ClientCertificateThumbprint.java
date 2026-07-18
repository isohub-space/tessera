package dev.tessera.iam.adapter.rest.token;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

/**
 * The trusted ingress contract for the client certificate that sender-constrains a
 * confidential client's tokens (RFC 8705), and the fail-closed parser that turns it into the
 * {@code x5t#S256} thumbprint placed in {@code cnf["x5t#S256"]}.
 *
 * <p><strong>Trust boundary.</strong> {@link #HEADER} is a <em>gateway-asserted</em> header,
 * exactly like {@code X-Tenant-Id}/{@code X-Subject-Id}: the deployment's edge terminates
 * mutual TLS, verifies the client certificate chain, and forwards the verified leaf
 * certificate here — stripping any client-supplied value first. The server does not terminate
 * mTLS itself. Crucially it does <em>not</em> trust a gateway-computed thumbprint: it
 * recomputes {@code SHA-256(DER)} from the forwarded certificate, so the binding value is
 * always the server's own computation over the actual certificate bytes.
 *
 * <p>The header may carry the certificate as PEM, URL-escaped PEM (e.g. nginx
 * {@code $ssl_client_escaped_cert}), or base64 DER; all three parse to the same DER and
 * thus the same thumbprint. Anything unparseable yields {@link Optional#empty()} — a
 * confidential client with no resolvable certificate is refused a token upstream.
 */
public final class ClientCertificateThumbprint {

    /** Gateway-asserted client-certificate header (PEM, URL-escaped PEM, or base64 DER). */
    public static final String HEADER = "X-Client-Certificate";

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private ClientCertificateThumbprint() {
    }

    /**
     * Computes the base64url {@code x5t#S256} thumbprint (RFC 8705 §3.1) of the client
     * certificate in the header, fail-closed.
     *
     * @param headerValue the {@value #HEADER} value, or {@code null} when absent
     * @return the thumbprint, or {@link Optional#empty()} when absent or unparseable
     */
    public static Optional<String> fromHeader(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) {
            return Optional.empty();
        }
        try {
            String value = headerValue.trim();
            if (value.indexOf('%') >= 0) {
                value = URLDecoder.decode(value, StandardCharsets.UTF_8);
            }
            byte[] certBytes = value.contains("BEGIN CERTIFICATE")
                    ? value.getBytes(StandardCharsets.UTF_8)
                    : Base64.getDecoder().decode(value.replaceAll("\\s", ""));

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certBytes));
            byte[] der = cert.getEncoded();
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(der);
            return Optional.of(B64URL.encodeToString(sha256));
        } catch (Exception unparseable) {
            // Fail closed: a malformed or unreadable certificate yields no binding.
            return Optional.empty();
        }
    }
}
