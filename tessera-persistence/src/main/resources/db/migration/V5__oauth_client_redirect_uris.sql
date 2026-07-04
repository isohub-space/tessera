-- V5 — registered redirect URIs for the authorization-code redirect-URI allow-list.
-- A client's redirect_uri must be pre-registered; /authorize exact-matches the requested
-- redirect_uri against this set BEFORE issuing a code (an unregistered URI is a non-redirectable
-- 400, never redirected — closing the open-redirect surface). Stored as whitespace-separated
-- exact URIs on oauth_client, nullable (a client may have none). The oauth_client RLS policy (V3)
-- is table-level and already governs this new column.

ALTER TABLE oauth_client ADD COLUMN redirect_uris TEXT;

COMMENT ON COLUMN oauth_client.redirect_uris IS
    'Whitespace-separated registered redirect URIs (exact-match allow-list for /authorize); NULL for a client with no registered URI.';
