package dev.tessera.iam.domain.authcode;

/**
 * A PKCE code challenge (RFC 7636 §4.3): the {@code code_challenge} value the client
 * sent on the authorization request, plus the {@link PkceMethod} used to derive it.
 *
 * <p>Immutable value object. The challenge is stored alongside the issued
 * authorization code ({@link AuthorizationGrant}); at the token endpoint the
 * presented {@code code_verifier} is folded back through {@link PkceVerifier} and
 * compared against it. Because {@link PkceMethod} can only be {@code S256}, a
 * {@code CodeChallenge} is always a SHA-256 challenge by construction.
 *
 * <p>The {@code value} is validated as a non-blank, RFC 7636-shaped base64url string
 * of the canonical S256 length (43 unpadded base64url characters encode the 32-byte
 * SHA-256 digest). Validating shape here keeps a malformed challenge from ever being
 * persisted with a code.
 *
 * @param method the challenge method (never {@code null}; always {@code S256})
 * @param value  the {@code code_challenge} (never {@code null} or blank; base64url)
 */
public record CodeChallenge(PkceMethod method, String value) {

    /** The exact length of a base64url-encoded SHA-256 digest, unpadded (32 bytes → 43 chars). */
    private static final int S256_CHALLENGE_LENGTH = 43;

    public CodeChallenge {
        if (method == null) {
            throw new IllegalArgumentException("CodeChallenge method must not be null");
        }
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CodeChallenge value must not be null or blank");
        }
        if (value.length() != S256_CHALLENGE_LENGTH || !Base64Url.isBase64Url(value)) {
            // RFC 7636 §4.2: an S256 challenge is base64url(SHA-256(verifier)) — exactly
            // 43 unpadded base64url characters. Anything else is a malformed challenge.
            throw new IllegalArgumentException(
                    "CodeChallenge value is not a valid base64url S256 challenge");
        }
    }

    /** Builds an {@code S256} code challenge from its wire value. */
    public static CodeChallenge s256(String value) {
        return new CodeChallenge(PkceMethod.S256, value);
    }
}
