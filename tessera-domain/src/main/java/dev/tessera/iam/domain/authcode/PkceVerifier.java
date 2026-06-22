package dev.tessera.iam.domain.authcode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Pure PKCE proof-of-possession check (RFC 7636 §4.6).
 *
 * <p>At the token endpoint the client presents a {@code code_verifier}; this verifier
 * recomputes the S256 challenge from it and compares the result against the
 * {@link CodeChallenge} that was stored with the authorization code. The comparison is
 * <strong>constant-time</strong> ({@link MessageDigest#isEqual}) so a mismatch cannot
 * be probed by timing.
 *
 * <p>Side-effect-free and framework-free: it reads no clock, no randomness and no I/O.
 * The verifier-format bounds (RFC 7636 §4.1: 43–128 unreserved characters) are enforced
 * here, so a malformed verifier is rejected as a non-match rather than hashing arbitrary
 * input.
 */
public final class PkceVerifier {

    /** RFC 7636 §4.1: the code verifier is 43–128 characters. */
    private static final int MIN_VERIFIER_LENGTH = 43;

    private static final int MAX_VERIFIER_LENGTH = 128;

    private PkceVerifier() {
    }

    /**
     * Verifies a presented {@code code_verifier} against a stored {@link CodeChallenge}.
     *
     * @param challenge    the challenge stored with the authorization code (never {@code null})
     * @param codeVerifier the {@code code_verifier} presented at the token endpoint
     *                     (may be {@code null}/blank — treated as a non-match)
     * @return {@code true} iff {@code S256(codeVerifier)} equals the stored challenge
     */
    public static boolean verifies(CodeChallenge challenge, String codeVerifier) {
        if (challenge == null) {
            throw new IllegalArgumentException("challenge must not be null");
        }
        if (codeVerifier == null || !isWellFormedVerifier(codeVerifier)) {
            return false;
        }
        String recomputed = Base64Url.s256Challenge(codeVerifier);
        // Constant-time comparison: never short-circuit on the first differing byte.
        return MessageDigest.isEqual(
                recomputed.getBytes(StandardCharsets.US_ASCII),
                challenge.value().getBytes(StandardCharsets.US_ASCII));
    }

    /** RFC 7636 §4.1: 43–128 chars from the unreserved set {@code [A-Za-z0-9-._~]}. */
    private static boolean isWellFormedVerifier(String verifier) {
        int len = verifier.length();
        if (len < MIN_VERIFIER_LENGTH || len > MAX_VERIFIER_LENGTH) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            char c = verifier.charAt(i);
            boolean unreserved = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~';
            if (!unreserved) {
                return false;
            }
        }
        return true;
    }
}
