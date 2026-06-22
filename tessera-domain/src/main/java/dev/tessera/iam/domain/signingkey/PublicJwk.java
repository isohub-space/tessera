package dev.tessera.iam.domain.signingkey;

/**
 * The public half of a signing key, modelled as the serialisable JWK parameters
 * (RFC 7517 / RFC 8037) — pure data, no cryptographic material or behaviour.
 *
 * <p>Only the members needed to publish an OKP/EC public verification key are carried:
 * {@code kty} (key type), {@code crv} (curve), {@code x} (the base64url-encoded public
 * coordinate), {@code kid}, {@code alg} and {@code use}. Private members
 * ({@code d}, …) are intentionally absent: this type can only ever represent a
 * <em>public</em> key, so a {@link PublicJwk} can never leak private material into the
 * JWKS.
 *
 * <p>Cryptography (key generation, the actual byte encoding) lives in the adapter
 * shell; the domain only owns the published shape.
 *
 * @param keyId     the {@code kid} (never {@code null})
 * @param algorithm the signing algorithm this key belongs to (never {@code null})
 * @param use       the public-key use (never {@code null})
 * @param x         base64url public coordinate / point encoding (never blank)
 * @param y         base64url Y coordinate for EC keys; {@code null} for OKP keys
 */
public record PublicJwk(KeyId keyId, SigningAlgorithm algorithm, KeyUse use, String x, String y) {

    public PublicJwk {
        if (keyId == null) {
            throw new IllegalArgumentException("PublicJwk keyId must not be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("PublicJwk algorithm must not be null");
        }
        if (use == null) {
            throw new IllegalArgumentException("PublicJwk use must not be null");
        }
        if (x == null || x.isBlank()) {
            throw new IllegalArgumentException("PublicJwk x must not be null or blank");
        }
    }

    /** The JWK {@code kty} member for this key. */
    public String keyType() {
        return algorithm.keyType();
    }

    /** The JWK {@code crv} member for this key. */
    public String curve() {
        return algorithm.curve();
    }
}
