/**
 * Credential / authentication-factor model for the Tessera domain
 *.
 *
 * <p>{@link dev.tessera.iam.domain.credential.Credential} is sealed over the four
 * supported factor kinds: {@link dev.tessera.iam.domain.credential.PasswordHash}
 * (Argon2id PHC), {@link dev.tessera.iam.domain.credential.WebAuthnAuthenticator}
 * (passkey public key), {@link dev.tessera.iam.domain.credential.TotpSecret} and
 * {@link dev.tessera.iam.domain.credential.RecoveryCode}.
 *
 * <p><strong>Raw secrets never live in the domain.</strong> Every member holds an
 * already-hashed or opaque verifier value; hashing, encryption and constant-time
 * comparison are adapter-shell concerns.
 */
package dev.tessera.iam.domain.credential;
