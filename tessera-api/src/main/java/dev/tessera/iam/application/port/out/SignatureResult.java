package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;

/**
 * The outcome of a signing operation performed <em>inside</em> the key provider: the
 * raw signature bytes plus the identity ({@code kid}) and algorithm of the key that
 * produced them, so the caller can stamp the JWS header.
 *
 * <p>The private key is never part of this result — only the signature it produced.
 *
 * @param keyId     the {@code kid} of the signing key (never {@code null})
 * @param algorithm the algorithm used (never {@code null})
 * @param signature the raw signature bytes (never {@code null})
 */
public record SignatureResult(KeyId keyId, SigningAlgorithm algorithm, byte[] signature) {

    public SignatureResult {
        if (keyId == null) {
            throw new IllegalArgumentException("SignatureResult keyId must not be null");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("SignatureResult algorithm must not be null");
        }
        if (signature == null) {
            throw new IllegalArgumentException("SignatureResult signature must not be null");
        }
        signature = signature.clone();
    }

    /** Defensive copy — the signature bytes are immutable to callers. */
    @Override
    public byte[] signature() {
        return signature.clone();
    }
}
