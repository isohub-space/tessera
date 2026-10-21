-- V8 — what a confidential client may obtain on its own behalf through the client_credentials
-- grant (RFC 6749 §4.4): its scopes, the audiences its tokens may name, and the roles they carry.
-- All three are registration data (configuration, never code), stored whitespace-separated like
-- redirect_uris and nullable: a client with no audience is issued no client_credentials token.
-- The oauth_client RLS policy (V3) is table-level and already governs these columns.

ALTER TABLE oauth_client ADD COLUMN allowed_scopes TEXT;
ALTER TABLE oauth_client ADD COLUMN audiences TEXT;
ALTER TABLE oauth_client ADD COLUMN roles TEXT;

COMMENT ON COLUMN oauth_client.allowed_scopes IS
    'Whitespace-separated scopes the client may be granted by client_credentials; NULL for none.';
COMMENT ON COLUMN oauth_client.audiences IS
    'Whitespace-separated audiences (aud) its client_credentials tokens may name; NULL for none.';
COMMENT ON COLUMN oauth_client.roles IS
    'Whitespace-separated roles its client_credentials tokens carry (a role cannot contain whitespace); NULL for none.';
