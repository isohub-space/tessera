package dev.tessera.iam.adapter.persistence.entity;

/**
 * Persisted discriminator for the kind of verifier-side credential material stored in
 * the {@code iam_credential} table.
 *
 * <p>Mirrors the sealed domain {@code Credential} hierarchy at the storage layer: the
 * enum name is written to the {@code kind} column ({@code VARCHAR(24)}), so the values
 * here must stay within that width and round-trip the persisted strings exactly.
 */
public enum CredentialKind {

    /** An Argon2id password hash (PHC string), stored as opaque bytes. */
    PASSWORD_HASH,

    /** A registered WebAuthn authenticator (stored public key + metadata). */
    WEBAUTHN,

    /** A TOTP shared secret. */
    TOTP,

    /** A hashed single-use recovery code. */
    RECOVERY_CODE
}
