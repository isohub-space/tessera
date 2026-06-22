package dev.tessera.iam.domain.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OidcCapabilities — the enforced capability set is the source of truth")
class OidcCapabilitiesTest {

    @Test
    @DisplayName("enforced() offers only the Authorization Code flow and the secure grants")
    void enforcedFlowAndGrants() {
        OidcCapabilities caps = OidcCapabilities.enforced();

        assertThat(caps.responseTypesSupported()).containsExactly("code");
        assertThat(caps.grantTypesSupported())
                .containsExactly("authorization_code", "refresh_token");
        // Insecure flows are deliberately absent.
        assertThat(caps.responseTypesSupported()).doesNotContain("token", "id_token");
        assertThat(caps.grantTypesSupported()).doesNotContain("implicit", "password");
    }

    @Test
    @DisplayName("PKCE is S256-only — the downgradeable 'plain' method is never offered")
    void pkceIsS256Only() {
        OidcCapabilities caps = OidcCapabilities.enforced();
        assertThat(caps.codeChallengeMethodsSupported()).containsExactly("S256");
        assertThat(caps.codeChallengeMethodsSupported()).doesNotContain("plain");
    }

    @Test
    @DisplayName("token signing advertises only asymmetric algs — no HS* MAC can ever appear")
    void signingAlgsAreAsymmetricOnly() {
        OidcCapabilities caps = OidcCapabilities.enforced();

        assertThat(caps.idTokenSigningAlgValuesSupported()).containsExactly("EdDSA", "ES256");
        assertThat(caps.dpopSigningAlgValuesSupported()).containsExactly("EdDSA", "ES256");
        // Symmetric MACs are unrepresentable in the signing model, so they never leak in.
        assertThat(caps.idTokenSigningAlgValuesSupported())
                .noneMatch(alg -> alg.startsWith("HS"));
        assertThat(caps.dpopSigningAlgValuesSupported())
                .noneMatch(alg -> alg.startsWith("HS"));
    }

    @Test
    @DisplayName("client auth, subject types, scopes and mTLS binding are the enforced set")
    void otherEnforcedMembers() {
        OidcCapabilities caps = OidcCapabilities.enforced();

        assertThat(caps.tokenEndpointAuthMethodsSupported())
                .containsExactly("client_secret_basic", "private_key_jwt", "tls_client_auth");
        assertThat(caps.subjectTypesSupported()).containsExactly("public");
        assertThat(caps.scopesSupported()).containsExactly("openid", "profile", "email");
        assertThat(caps.tlsClientCertificateBoundAccessTokens()).isTrue();
    }
}
