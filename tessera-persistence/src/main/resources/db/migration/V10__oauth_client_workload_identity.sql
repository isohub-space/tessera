-- V10 — keyless (workload identity) clients: a client that authenticates with a JWT a trusted
-- external issuer, such as a cloud platform, issues to its running workload. The client stores no
-- credential; its registration names the issuer and the subject the token must carry. Which issuers
-- are trusted is operator configuration, not data. A WORKLOAD_IDENTITY client has an issuer and a
-- subject and neither a secret nor keys; no other client has an issuer or subject. The columns are
-- new and all NULL, so the constraints are created valid. The oauth_client RLS policy (V3) is
-- table-level and already governs both columns.

ALTER TABLE oauth_client ADD COLUMN assertion_issuer VARCHAR(512);
ALTER TABLE oauth_client ADD COLUMN assertion_subject VARCHAR(512);

ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_workload_identity_shape
    CHECK (auth_method IS DISTINCT FROM 'WORKLOAD_IDENTITY'
        OR (secret_hash IS NULL AND jwks IS NULL
            AND assertion_issuer IS NOT NULL AND assertion_subject IS NOT NULL));
ALTER TABLE oauth_client ADD CONSTRAINT ck_oauth_client_issuer_only_for_workload_identity
    CHECK ((assertion_issuer IS NULL AND assertion_subject IS NULL) OR auth_method = 'WORKLOAD_IDENTITY');

-- One workload is one client: its token's audience is tessera's single issuer, not a realm, so an
-- issuer and subject registered twice would let one workload act as either client, in any tenant.
-- The index is global across tenants on purpose (a uniqueness check is not filtered by row-level
-- security), so a second registration of the same pair is refused wherever it is made.
CREATE UNIQUE INDEX uq_oauth_client_workload_identity
    ON oauth_client (assertion_issuer, assertion_subject)
    WHERE auth_method = 'WORKLOAD_IDENTITY';

COMMENT ON COLUMN oauth_client.assertion_issuer IS
    'The iss a WORKLOAD_IDENTITY client''s token must carry; it must also be a configured trusted issuer. NULL for every other client.';
COMMENT ON COLUMN oauth_client.assertion_subject IS
    'The sub a WORKLOAD_IDENTITY client''s token must carry. NULL for every other client.';
