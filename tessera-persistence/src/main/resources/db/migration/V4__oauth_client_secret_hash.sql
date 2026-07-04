-- V4 — confidential-client secret material.
-- A client secret is a property of the CLIENT, not of a user, so it does not belong in
-- iam_credential (which is user-scoped: user_id NOT NULL). Store it on oauth_client as an
-- Argon2id PHC string (never plaintext), nullable: public clients hold no secret, and a
-- confidential client using MTLS or PRIVATE_KEY_JWT authenticates without a shared secret.
-- The oauth_client RLS policy (V3) is table-level and already governs this new column, so
-- no policy change is needed; the secret is only ever read inside a tenant-scoped session.

ALTER TABLE oauth_client ADD COLUMN secret_hash TEXT;

COMMENT ON COLUMN oauth_client.secret_hash IS
    'Argon2id PHC string for a confidential client authenticating by shared secret; never plaintext. NULL for public clients and for confidential clients using MTLS/PRIVATE_KEY_JWT.';
