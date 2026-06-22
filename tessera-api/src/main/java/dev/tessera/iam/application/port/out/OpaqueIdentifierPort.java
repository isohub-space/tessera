package dev.tessera.iam.application.port.out;

/**
 * Outbound port that mints cryptographically-random opaque identifiers — authorization
 * codes and token {@code jti}s.
 *
 * <p>Randomness is an effect: the functional core reads no entropy, so generating an
 * unguessable code or token id lives behind this port and is supplied by an adapter
 * backed by a CSPRNG ({@code SecureRandom}). An authorization code must carry enough
 * entropy that it cannot be guessed (RFC 6749 §10.10); the implementation returns a
 * base64url string of at least 256 bits.
 */
public interface OpaqueIdentifierPort {

    /**
     * @return a fresh, unguessable authorization code (base64url, ≥256 bits of entropy)
     */
    String newAuthorizationCode();

    /**
     * @return a fresh, unique token identifier suitable for a JWT {@code jti} claim
     */
    String newTokenId();
}
