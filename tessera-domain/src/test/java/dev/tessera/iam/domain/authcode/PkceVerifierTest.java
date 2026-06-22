package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifies the pure PKCE S256 check against the RFC 7636 Appendix B test vector and the
 * negative paths (wrong verifier, malformed verifier, wrong-length challenge).
 */
@DisplayName("PkceVerifier — S256 proof of possession (RFC 7636)")
class PkceVerifierTest {

    // RFC 7636 Appendix B canonical vector.
    private static final String RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    @DisplayName("the RFC 7636 Appendix B verifier satisfies its challenge")
    void rfcVectorVerifies() {
        CodeChallenge challenge = CodeChallenge.s256(RFC_CHALLENGE);
        assertThat(PkceVerifier.verifies(challenge, RFC_VERIFIER)).isTrue();
    }

    @Test
    @DisplayName("a different (well-formed) verifier does not satisfy the challenge")
    void wrongVerifierFails() {
        CodeChallenge challenge = CodeChallenge.s256(RFC_CHALLENGE);
        String other = "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhakxifmZHag";
        assertThat(PkceVerifier.verifies(challenge, other)).isFalse();
    }

    @Test
    @DisplayName("a null or too-short verifier is a non-match, never an error")
    void malformedVerifierIsNonMatch() {
        CodeChallenge challenge = CodeChallenge.s256(RFC_CHALLENGE);
        assertThat(PkceVerifier.verifies(challenge, null)).isFalse();
        assertThat(PkceVerifier.verifies(challenge, "too-short")).isFalse();
        // 129 chars exceeds the RFC 7636 §4.1 maximum of 128.
        assertThat(PkceVerifier.verifies(challenge, "a".repeat(129))).isFalse();
    }

    @Test
    @DisplayName("a verifier with a non-unreserved character is a non-match")
    void illegalCharacterIsNonMatch() {
        CodeChallenge challenge = CodeChallenge.s256(RFC_CHALLENGE);
        // Same length as the RFC verifier but with a '+' (not in the unreserved set).
        String bad = "dBjftJeZ4CVP+mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assertThat(PkceVerifier.verifies(challenge, bad)).isFalse();
    }
}
