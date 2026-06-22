package dev.tessera.iam.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SigningAlgorithm — asymmetric-only signing algorithm model")
class SigningAlgorithmTest {

    @Test
    @DisplayName("EdDSA is the default algorithm")
    void eddsaIsDefault() {
        assertThat(SigningAlgorithm.defaultAlgorithm()).isEqualTo(SigningAlgorithm.EdDSA);
    }

    @Test
    @DisplayName("only asymmetric algorithms are representable — HS* is not a member")
    void onlyAsymmetricAlgorithmsExist() {
        // The whole point: a symmetric MAC family cannot be named, so it can never be
        // selected for signing. Asserting the exact member set locks that in.
        assertThat(SigningAlgorithm.values())
                .containsExactlyInAnyOrder(SigningAlgorithm.EdDSA, SigningAlgorithm.ES256);

        for (SigningAlgorithm alg : SigningAlgorithm.values()) {
            assertThat(alg.name()).doesNotStartWith("HS");
        }
    }

    @Test
    @DisplayName("EdDSA maps to OKP/Ed25519, ES256 maps to EC/P-256")
    void jwkParametersAreExposed() {
        assertThat(SigningAlgorithm.EdDSA.keyType()).isEqualTo("OKP");
        assertThat(SigningAlgorithm.EdDSA.curve()).isEqualTo("Ed25519");
        assertThat(SigningAlgorithm.EdDSA.algIdentifier()).isEqualTo("EdDSA");

        assertThat(SigningAlgorithm.ES256.keyType()).isEqualTo("EC");
        assertThat(SigningAlgorithm.ES256.curve()).isEqualTo("P-256");
        assertThat(SigningAlgorithm.ES256.algIdentifier()).isEqualTo("ES256");
    }
}
