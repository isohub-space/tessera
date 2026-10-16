-- V7 — refresh-token families: rotation instant and salt (reuse grace), and the granted scope.
--
-- Reuse grace (iam.refresh.reuse-grace, off by default). A confidential client that sends
-- concurrent requests with one refresh token presents it twice; strict rotation treats the second
-- presentation as a replay and revokes the family. With a grace configured, the token the last
-- rotation superseded, presented again by the same confidential client shortly after that
-- rotation, receives the same successor instead. This is a deliberate, bounded relaxation of
-- strict rotation, of the kind several authorization servers offer as a refresh-token "reuse
-- interval" or "grace period". It is never applied to public clients, and within the window a
-- predecessor presented by a party that also holds the client's credentials is not detected.
--
-- rotated_at bounds the window. rotation_salt is the random salt the successor's secret was
-- derived with, so the server key and an old token alone cannot compute a newer token.
--
-- granted_scope records the scopes of the original grant, so a refresh can re-issue an ID token
-- when that grant included openid (OpenID Connect Core 1.0 §12.2).

ALTER TABLE refresh_token_family
    ADD COLUMN rotated_at    TIMESTAMPTZ,
    ADD COLUMN rotation_salt TEXT,
    ADD COLUMN granted_scope TEXT;

COMMENT ON COLUMN refresh_token_family.rotated_at IS
    'When the family last rotated; NULL until its first rotation. The reuse grace runs from here.';
COMMENT ON COLUMN refresh_token_family.rotation_salt IS
    'Random salt of the last rotation, an input to the successor derivation; NULL when unsalted.';
COMMENT ON COLUMN refresh_token_family.granted_scope IS
    'Space-separated scopes of the original grant; NULL for families created before V7.';

-- (No index: these columns are read only with the row the primary key already locates. The V3
-- row-level-security policy on refresh_token_family is table-level and governs them.)
