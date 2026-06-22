package dev.tessera.iam.domain.signingkey;

import java.time.Instant;

/**
 * An immutable snapshot of a signing key as the rotation policy reasons about it —
 * its identity, algorithm, public JWK, lifecycle {@link SigningKeyState state} and the
 * instant it became {@link SigningKeyState#ACTIVE} (if ever).
 *
 * <p>This is a pure projection: it carries no private key bytes and no clock. Time
 * enters the policy only as a parameter (see {@link KeyRotationPolicy}); a descriptor
 * merely records <em>when</em> the key was activated so the policy can compare that
 * against a max signing TTL supplied by the caller.
 *
 * @param keyId       the key identity (never {@code null})
 * @param publicJwk   the published public JWK (never {@code null})
 * @param state       the current lifecycle state (never {@code null})
 * @param activatedAt the instant the key became {@code ACTIVE}, or {@code null} if it
 *                    has never been activated
 */
public record SigningKeyDescriptor(
        KeyId keyId, PublicJwk publicJwk, SigningKeyState state, Instant activatedAt) {

    public SigningKeyDescriptor {
        if (keyId == null) {
            throw new IllegalArgumentException("SigningKeyDescriptor keyId must not be null");
        }
        if (publicJwk == null) {
            throw new IllegalArgumentException("SigningKeyDescriptor publicJwk must not be null");
        }
        if (state == null) {
            throw new IllegalArgumentException("SigningKeyDescriptor state must not be null");
        }
    }

    /** The signing algorithm, derived from the public JWK. */
    public SigningAlgorithm algorithm() {
        return publicJwk.algorithm();
    }

    /** The JWK {@code use} of this key, derived from the public JWK. */
    public KeyUse use() {
        return publicJwk.use();
    }

    /** Whether this key may currently sign newly issued tokens (only {@code ACTIVE} may). */
    public boolean canSign() {
        return state == SigningKeyState.ACTIVE;
    }

    /** Whether this key is published in the JWKS (ACTIVE or RETIRING keys are). */
    public boolean isPublished() {
        return state == SigningKeyState.ACTIVE || state == SigningKeyState.RETIRING;
    }
}
