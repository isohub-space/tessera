package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClientCertificateThumbprint — x5t#S256 from the gateway-asserted certificate")
class ClientCertificateThumbprintTest {

    @Test
    @DisplayName("a PEM certificate yields its RFC 8705 x5t#S256 thumbprint")
    void pemThumbprint() {
        assertThat(ClientCertificateThumbprint.fromHeader(TestClientCertificate.PEM))
                .contains(TestClientCertificate.X5T_S256);
    }

    @Test
    @DisplayName("URL-escaped PEM (e.g. nginx $ssl_client_escaped_cert) yields the same thumbprint")
    void urlEscapedPemThumbprint() {
        String escaped = URLEncoder.encode(TestClientCertificate.PEM, StandardCharsets.UTF_8);
        assertThat(ClientCertificateThumbprint.fromHeader(escaped))
                .contains(TestClientCertificate.X5T_S256);
    }

    @Test
    @DisplayName("base64 DER yields the same thumbprint as the PEM")
    void base64DerThumbprint() {
        String der = TestClientCertificate.PEM
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        assertThat(ClientCertificateThumbprint.fromHeader(der))
                .contains(TestClientCertificate.X5T_S256);
    }

    @Test
    @DisplayName("a null, blank, or unparseable header yields empty (fail closed)")
    void unparseableIsEmpty() {
        assertThat(ClientCertificateThumbprint.fromHeader(null)).isEmpty();
        assertThat(ClientCertificateThumbprint.fromHeader("   ")).isEmpty();
        assertThat(ClientCertificateThumbprint.fromHeader("not-a-certificate")).isEmpty();
        // Valid base64 but not a certificate.
        assertThat(ClientCertificateThumbprint.fromHeader(
                Base64.getEncoder().encodeToString("nonsense".getBytes(StandardCharsets.UTF_8))))
                .isEqualTo(Optional.empty());
    }
}
