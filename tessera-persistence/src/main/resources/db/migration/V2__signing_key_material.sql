-- Signing-key material: envelope-encrypted private key + selection metadata.
--
-- V1 created `signing_key` carrying only the PUBLIC JWK (it backed a readiness gate).
-- This migration adds the columns needed to actually sign:
--   * the private key, stored ENVELOPE-ENCRYPTED (never in cleartext): an AES-256-GCM
--     ciphertext (`private_key_enc`) with its nonce (`private_key_nonce`) and the
--     wrapped per-key data-encryption key (`dek_wrapped`). The DEK is itself wrapped
--     (AES-GCM key-wrap) by a master key held outside the database; the master key
--     never lands in a row. A production deployment swaps the master-key step for a
--     KMS/HSM behind the same provider port — the column shape is unchanged.
--   * `key_use` and `issuer`, so a signing key can be selected by (tenant, issuer, use)
--     — the lookup a token signer performs per realm.
--
-- The columns live on the same RLS-protected table, so they inherit signing_key's
-- FORCE ROW LEVEL SECURITY policy unchanged: private material is only ever readable by
-- a transaction bound to the owning tenant, and the schema still fails closed when no
-- `app.tenant_id` is set.

ALTER TABLE signing_key
    ADD COLUMN private_key_enc   BYTEA,                              -- AES-256-GCM ciphertext of the private key
    ADD COLUMN private_key_nonce BYTEA,                              -- 96-bit GCM nonce for private_key_enc
    ADD COLUMN dek_wrapped       BYTEA,                              -- per-key data key, wrapped by the master key
    ADD COLUMN key_use           VARCHAR(8)  NOT NULL DEFAULT 'sig', -- JWK "use": sig | enc
    ADD COLUMN issuer            TEXT,                               -- token issuer (iss) this key signs for
    ADD COLUMN activated_at      TIMESTAMPTZ;                        -- instant the key became ACTIVE (for TTL)

-- Selection index: a signer resolves the ACTIVE key for (tenant, issuer, use).
CREATE INDEX idx_signing_key_selection ON signing_key (tenant_id, issuer, key_use, state);

COMMENT ON COLUMN signing_key.private_key_enc IS
    'Envelope-encrypted private key (AES-256-GCM ciphertext); never stored in cleartext.';
COMMENT ON COLUMN signing_key.dek_wrapped IS
    'Per-key data-encryption key, wrapped by the master key (KMS/HSM in production).';
