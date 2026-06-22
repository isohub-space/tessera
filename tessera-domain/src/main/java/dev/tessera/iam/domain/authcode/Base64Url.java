package dev.tessera.iam.domain.authcode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Pure base64url / SHA-256 helpers for the PKCE flow.
 *
 * <p>Framework-free and side-effect-free: only the JDK's {@link MessageDigest} and
 * {@link Base64} are used (both pure, deterministic primitives). No JOSE library, no
 * crypto adapter — PKCE's challenge derivation is a one-line hash that belongs in the
 * functional core so it can be unit-tested without booting a container.
 */
final class Base64Url {

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private Base64Url() {
    }

    /**
     * Computes the PKCE S256 challenge for a code verifier:
     * {@code BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))} (RFC 7636 §4.2).
     *
     * @param codeVerifier the raw {@code code_verifier} (US-ASCII per RFC 7636 §4.1)
     * @return the base64url-encoded SHA-256 challenge, unpadded
     */
    static String s256Challenge(String codeVerifier) {
        byte[] digest = sha256(codeVerifier.getBytes(StandardCharsets.US_ASCII));
        return URL_ENCODER.encodeToString(digest);
    }

    /** SHA-256 of the given bytes; SHA-256 is a mandatory JDK algorithm so this never fails. */
    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required of every conformant JDK (JCA spec); unreachable.
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }

    /** @return {@code true} if every character is in the base64url alphabet (no padding). */
    static boolean isBase64Url(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }
}
