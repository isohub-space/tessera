package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Validates {@link CodeChallenge} shape rules and the S256-only {@link PkceMethod}. */
@DisplayName("CodeChallenge — S256 challenge value object")
class CodeChallengeTest {

    private static final String VALID = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    @DisplayName("accepts a canonical 43-char base64url S256 challenge")
    void acceptsValid() {
        CodeChallenge challenge = CodeChallenge.s256(VALID);
        assertThat(challenge.method()).isEqualTo(PkceMethod.S256);
        assertThat(challenge.value()).isEqualTo(VALID);
    }

    @Test
    @DisplayName("rejects a blank challenge")
    void rejectsBlank() {
        assertThatThrownBy(() -> CodeChallenge.s256(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects a challenge of the wrong length")
    void rejectsWrongLength() {
        assertThatThrownBy(() -> CodeChallenge.s256("tooshort"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("rejects a challenge with non-base64url characters")
    void rejectsNonBase64Url() {
        // 43 chars, but contains '+' and '/' which are base64 (not base64url).
        String bad = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+/M";
        assertThatThrownBy(() -> CodeChallenge.s256(bad))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("PkceMethod has only S256 — plain is unrepresentable")
    void onlyS256() {
        assertThat(PkceMethod.values()).containsExactly(PkceMethod.S256);
        assertThat(PkceMethod.S256.wireValue()).isEqualTo("S256");
    }
}
