package dev.tessera.iam.domain.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("DiscoveryDocument — generated from the enforced capability set")
class DiscoveryDocumentTest {

    private static final String ISSUER = "https://issuer.example";

    @Test
    @DisplayName("forIssuer builds issuer-relative endpoint URLs")
    void issuerRelativeEndpoints() {
        DiscoveryDocument doc =
                DiscoveryDocument.forIssuer(ISSUER, OidcCapabilities.enforced());

        assertThat(doc.issuer()).isEqualTo(ISSUER);
        assertThat(doc.jwksUri()).isEqualTo(ISSUER + "/jwks");
        assertThat(doc.authorizationEndpoint()).isEqualTo(ISSUER + "/authorize");
        assertThat(doc.tokenEndpoint()).isEqualTo(ISSUER + "/token");
        assertThat(doc.userinfoEndpoint()).isEqualTo(ISSUER + "/userinfo");
    }

    @Test
    @DisplayName("a trailing slash on the issuer does not produce a double slash in endpoints")
    void trailingSlashIssuer() {
        DiscoveryDocument doc =
                DiscoveryDocument.forIssuer(ISSUER + "/", OidcCapabilities.enforced());

        assertThat(doc.issuer()).isEqualTo(ISSUER + "/");
        assertThat(doc.jwksUri()).isEqualTo(ISSUER + "/jwks");
        assertThat(doc.tokenEndpoint()).isEqualTo(ISSUER + "/token");
    }

    @Test
    @DisplayName("capability values are copied verbatim from the capability set")
    void copiesCapabilityValues() {
        OidcCapabilities caps = OidcCapabilities.enforced();
        DiscoveryDocument doc = DiscoveryDocument.forIssuer(ISSUER, caps);

        assertThat(doc.responseTypesSupported()).isEqualTo(caps.responseTypesSupported());
        assertThat(doc.grantTypesSupported()).isEqualTo(caps.grantTypesSupported());
        assertThat(doc.codeChallengeMethodsSupported())
                .isEqualTo(caps.codeChallengeMethodsSupported());
        assertThat(doc.tokenEndpointAuthMethodsSupported())
                .isEqualTo(caps.tokenEndpointAuthMethodsSupported());
        assertThat(doc.subjectTypesSupported()).isEqualTo(caps.subjectTypesSupported());
        assertThat(doc.idTokenSigningAlgValuesSupported())
                .isEqualTo(caps.idTokenSigningAlgValuesSupported());
        assertThat(doc.dpopSigningAlgValuesSupported())
                .isEqualTo(caps.dpopSigningAlgValuesSupported());
        assertThat(doc.scopesSupported()).isEqualTo(caps.scopesSupported());
        assertThat(doc.tlsClientCertificateBoundAccessTokens())
                .isEqualTo(caps.tlsClientCertificateBoundAccessTokens());
    }

    @Test
    @DisplayName("a blank issuer is rejected")
    void blankIssuerRejected() {
        OidcCapabilities caps = OidcCapabilities.enforced();
        assertThatThrownBy(() -> DiscoveryDocument.forIssuer("  ", caps))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> DiscoveryDocument.forIssuer(null, caps))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
