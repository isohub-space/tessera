-- V11 — registered post-logout redirect URIs for RP-initiated logout (OpenID Connect
-- RP-Initiated Logout 1.0). The end-session endpoint exact-matches a requested
-- post_logout_redirect_uri against this set BEFORE redirecting; an unregistered URI is a
-- non-redirectable 400, never followed. Kept apart from redirect_uris: a URI registered to receive
-- an authorization code is not thereby a place a signed-out browser may be sent. Stored as
-- whitespace-separated exact URIs on oauth_client, nullable (a client may have none). The
-- oauth_client RLS policy (V3) is table-level and already governs this new column.

ALTER TABLE oauth_client ADD COLUMN post_logout_redirect_uris TEXT;

COMMENT ON COLUMN oauth_client.post_logout_redirect_uris IS
    'Whitespace-separated registered post-logout redirect URIs (exact-match allow-list for the end-session endpoint); NULL for a client never redirected after logout.';
