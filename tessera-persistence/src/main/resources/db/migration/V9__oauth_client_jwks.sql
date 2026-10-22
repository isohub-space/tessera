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

-- The key set itself is checked as well, since it is parsed on every request that names the
-- client: at most 16 KiB of JSON whose "keys" array holds 1 to 10 keys, none with a private or
-- symmetric member (RFC 7518 §6.2.2, §6.3.2, §6.4.1). Created valid, as the column is new and
-- all NULL. A malformed value fails the cast and is refused with it; COALESCE refuses a value
-- whose shape makes the expression NULL.
ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_jwks_public_and_bounded
    CHECK (jwks IS NULL OR COALESCE(
        octet_length(jwks) <= 16384
        AND jsonb_typeof(jwks::jsonb -> 'keys') = 'array'
        AND jsonb_array_length(jwks::jsonb -> 'keys') BETWEEN 1 AND 10
        AND NOT jsonb_path_exists(jwks::jsonb,
            '$.keys[*] ? (exists(@.d) || exists(@.p) || exists(@.q) || exists(@.dp) || exists(@.dq) || exists(@.qi) || exists(@.oth) || exists(@.k))'),
        false));

COMMENT ON COLUMN oauth_client.jwks IS
    'JWK Set JSON of the public keys a PRIVATE_KEY_JWT client signs its client assertions with; NULL for every other client.';
