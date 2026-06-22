package dev.tessera.iam.domain.credential;

/**
 * A stored authentication factor for a user.
 *
 * <p>Sealed over the factor kinds the design supports. Each member holds only an
 * <strong>already-hashed / opaque</strong> value — see the per-member javadoc.
 *
 * <p><strong>Security invariant: raw secrets never live in the domain.</strong>
 * A {@code Credential} models the <em>verifier-side</em> material (a PHC hash, a
 * stored WebAuthn public key, a TOTP shared secret, a hashed recovery code), not a
 * plaintext password or a live OTP. Hashing/encryption and constant-time
 * comparison happen in the adapter shell; the domain only carries the result.
 */
public sealed interface Credential
        permits PasswordHash, WebAuthnAuthenticator, TotpSecret, RecoveryCode {
}
