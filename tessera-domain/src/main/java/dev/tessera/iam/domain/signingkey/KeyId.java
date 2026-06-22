package dev.tessera.iam.domain.signingkey;

/**
 * A JWK key identifier ({@code kid}) — the stable handle a verifier reads from a JWS
 * header to select the matching public key from the JWKS.
 *
 * <p>Framework-free value object. The {@code kid} is opaque: it carries no semantics
 * beyond uniquely naming a key within an issuer, and must be non-blank.
 *
 * @param value the {@code kid} string (never {@code null} or blank)
 */
public record KeyId(String value) {

    public KeyId {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("KeyId value must not be null or blank");
        }
    }

    /** Builds a {@link KeyId} from its string form. */
    public static KeyId of(String value) {
        return new KeyId(value);
    }
}
