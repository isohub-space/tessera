package dev.tessera.iam.launcher.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.persistence.signingkey.SigningKeyConfig;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The two issuer settings can no longer silently disagree.
 *
 * <p>{@code iam.oidc.issuer} is what discovery advertises and what tokens carry;
 * {@code iam.keys.issuer} is stamped on every minted signing key. They used to default to
 * different values ({@code http://localhost:8080} vs {@code https://localhost:8090}) with
 * nothing tying them together, so a deployment that set one and not the other signed under
 * one issuer identity while advertising another — and said nothing about it.
 *
 * <p>The first test fails against main: under {@code %test}, {@code iam.oidc.issuer} is
 * {@code https://issuer.test.example} while {@code iam.keys.issuer} still fell back to its
 * own unrelated default.
 */
@QuarkusTest
@DisplayName("Issuer settings — derived by default, never silently divergent")
class IssuerConsistencyTest {

    @Inject
    OidcDiscoveryConfig oidc;

    @Inject
    SigningKeyConfig keys;

    @Test
    @DisplayName("iam.keys.issuer derives from iam.oidc.issuer when it is not set explicitly")
    void keysIssuerDerivesFromOidcIssuer() {
        assertThat(keys.issuer())
                .as("the signing-key issuer must follow the advertised issuer")
                .isEqualTo(oidc.issuer());
    }

    @Test
    @DisplayName("a disagreeing pair aborts startup with a message naming both values")
    void disagreementIsRefused() {
        assertThatThrownBy(() -> IssuerConsistencyCheck.verify(
                        "https://iam.example.com", "https://localhost:8090"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("iam.oidc.issuer")
                .hasMessageContaining("https://iam.example.com")
                .hasMessageContaining("iam.keys.issuer")
                .hasMessageContaining("https://localhost:8090");
    }

    @Test
    @DisplayName("an issuer differing only by a trailing slash is a DIFFERENT issuer")
    void trailingSlashIsNotEquality() {
        // An issuer identifier is compared character-for-character by relying parties
        // (OIDC Core §3.1.3.7), so normalising here would hide a real mismatch.
        assertThatThrownBy(() -> IssuerConsistencyCheck.verify(
                        "https://iam.example.com", "https://iam.example.com/"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("an agreeing pair passes")
    void agreementPasses() {
        IssuerConsistencyCheck.verify("https://iam.example.com", "https://iam.example.com");
    }
}
