package dev.tessera.iam.application.port.out;

/**
 * Outbound port that mints cryptographically-random opaque identifiers — authorization
 * codes, token {@code jti}s, refresh-token secrets, and refresh-family ids.
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

    /**
     * @return a fresh, unguessable refresh-token secret (base64url, ≥256 bits of entropy). Being
     *         high-entropy and server-minted, it is stored as a fast one-way hash (not a
     *         memory-hard KDF), unlike a user-chosen client secret.
     */
    String newRefreshToken();

    /**
     * @return a fresh identifier for a refresh-token family — a time-ordered UUID (v7), matching the
     *         append-heavy family primary key. Embedded (non-secret) in the opaque refresh token so a
     *         presented token routes to its family without a request header.
     */
    java.util.UUID newFamilyId();
}
