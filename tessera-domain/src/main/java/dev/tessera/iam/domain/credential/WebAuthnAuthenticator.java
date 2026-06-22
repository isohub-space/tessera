package dev.tessera.iam.domain.credential;

import java.util.Arrays;

/**
 * A registered WebAuthn / passkey authenticator.
 *
 * <p>Holds the public-key material needed to verify an assertion — never any
 * private key (that stays on the user's device/authenticator). The signature
 * counter guards against authenticator cloning (it must strictly increase across
 * assertions).
 *
 * @param credentialId the opaque WebAuthn credential id (defensively copied, never
 *                     {@code null} or empty)
 * @param publicKeyCose the COSE-encoded public key (defensively copied, never
 *                     {@code null} or empty)
 * @param signatureCount the last-seen signature counter (never negative)
 */
public record WebAuthnAuthenticator(
        byte[] credentialId,
        byte[] publicKeyCose,
        long signatureCount) implements Credential {

    public WebAuthnAuthenticator {
        if (credentialId == null || credentialId.length == 0) {
            throw new IllegalArgumentException("WebAuthnAuthenticator credentialId must not be empty");
        }
        if (publicKeyCose == null || publicKeyCose.length == 0) {
            throw new IllegalArgumentException("WebAuthnAuthenticator publicKeyCose must not be empty");
        }
        if (signatureCount < 0) {
            throw new IllegalArgumentException("WebAuthnAuthenticator signatureCount must not be negative");
        }
        // Defensive copies: byte[] is mutable, so copy on the way in to keep the
        // record genuinely immutable.
        credentialId = credentialId.clone();
        publicKeyCose = publicKeyCose.clone();
    }

    /** @return a defensive copy of the credential id. */
    @Override
    public byte[] credentialId() {
        return credentialId.clone();
    }

    /** @return a defensive copy of the COSE public key. */
    @Override
    public byte[] publicKeyCose() {
        return publicKeyCose.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof WebAuthnAuthenticator other)) {
            return false;
        }
        return signatureCount == other.signatureCount
                && Arrays.equals(credentialId, other.credentialId)
                && Arrays.equals(publicKeyCose, other.publicKeyCose);
    }

    @Override
    public int hashCode() {
        int result = Long.hashCode(signatureCount);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(publicKeyCose);
        return result;
    }

    @Override
    public String toString() {
        // Avoid leaking key bytes in logs; lengths are enough for diagnostics.
        return "WebAuthnAuthenticator[credentialId=" + credentialId.length + "b, publicKeyCose="
                + publicKeyCose.length + "b, signatureCount=" + signatureCount + "]";
    }
}
