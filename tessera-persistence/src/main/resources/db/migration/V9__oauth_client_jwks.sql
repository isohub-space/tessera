-- V9 — the public keys a private_key_jwt client signs its client assertions with (RFC 7523).
-- A JWK Set (RFC 7517) as JSON text, registration data like redirect_uris, and public material
-- only: nothing here is a secret. A client authenticates with one method, so a private_key_jwt
-- client holds no secret and only a private_key_jwt client holds keys. The two constraints are
-- NOT VALID so that a row written before this migration does not block it; every new or updated
-- row is checked. The oauth_client RLS policy (V3) is table-level and already governs the column.

ALTER TABLE oauth_client ADD COLUMN jwks TEXT;

ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_key_auth_has_no_secret
    CHECK (auth_method IS DISTINCT FROM 'PRIVATE_KEY_JWT' OR secret_hash IS NULL) NOT VALID;
ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_jwks_only_for_key_auth
    CHECK (jwks IS NULL OR auth_method = 'PRIVATE_KEY_JWT') NOT VALID;

COMMENT ON COLUMN oauth_client.jwks IS
    'JWK Set JSON of the public keys a PRIVATE_KEY_JWT client signs its client assertions with; NULL for every other client.';
