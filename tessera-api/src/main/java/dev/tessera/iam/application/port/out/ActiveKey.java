package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;

/**
 * The realm's current signing key as seen by callers that need to sign a token: its
 * {@code kid}, algorithm and public JWK — but never the private key material.
 *
 * <p>A caller uses the {@link #keyId()} and {@link #algorithm()} to build the JWS
 * header, then asks the {@link KeyProviderPort} to sign; the private key stays inside
 * the provider.
 *
 * @param keyId     the current signing key's {@code kid} (never {@code null})
 * @param algorithm its algorithm (never {@code null})
 * @param publicJwk its public JWK (never {@code null})
 */
public record ActiveKey(KeyId keyId, SigningAlgorithm algorithm, PublicJwk publicJwk) {

    public ActiveKey {
        if (keyId == null) {
            throw new IllegalArgumentException("ActiveKey keyId must not be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("ActiveKey algorithm must not be null");
        }
        if (publicJwk == null) {
            throw new IllegalArgumentException("ActiveKey publicJwk must not be null");
        }
    }
}
