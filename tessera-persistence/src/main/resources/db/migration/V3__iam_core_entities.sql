-- V3 — core IAM domain tables: users, credentials, clients, sessions, consents and
-- refresh-token families. Every table here is tenant-scoped and follows the V1 RLS
-- idiom unchanged: each carries `tenant_id` and a policy comparing it to the
-- per-transaction GUC `app.tenant_id`. `current_setting('app.tenant_id', true)`
-- returns NULL (or an empty string on a pooled connection) when no tenant is bound;
-- `NULLIF(..., '')::uuid` normalises both to NULL, so the predicate evaluates to NULL
-- → the row is invisible and writes are rejected. The schema FAILS CLOSED when no
-- tenant is bound, and FORCE ROW LEVEL SECURITY makes the policies apply even to the
-- table owner (iam_migrator). DML grants to iam_app are inherited automatically from
-- the ALTER DEFAULT PRIVILEGES set up in V1, so no grants are repeated here.

-- ---------------------------------------------------------------------------
-- Users & credentials
-- ---------------------------------------------------------------------------

CREATE TABLE iam_user (
    id          UUID         NOT NULL,
    tenant_id   UUID         NOT NULL,
    baseline_id UUID         NOT NULL,
    subject_id  TEXT         NOT NULL,          -- stable OIDC `sub`
    username    TEXT,                           -- optional login identifier
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_iam_user        PRIMARY KEY (id),
    CONSTRAINT uq_iam_user_subject UNIQUE (tenant_id, baseline_id, subject_id)
);

CREATE TABLE iam_credential (
    id          UUID         NOT NULL,
    tenant_id   UUID         NOT NULL,
    baseline_id UUID         NOT NULL,
    user_id     UUID         NOT NULL,
    kind        VARCHAR(24)  NOT NULL,          -- PASSWORD_HASH | WEBAUTHN | TOTP | RECOVERY_CODE
    material    BYTEA        NOT NULL,          -- already-hashed / opaque verifier-side material; never plaintext
    label       TEXT,                           -- optional user-facing label (e.g. authenticator name)
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_iam_credential PRIMARY KEY (id)
);

CREATE INDEX idx_iam_credential_user ON iam_credential (tenant_id, user_id);

-- ---------------------------------------------------------------------------
-- OAuth/OIDC clients
-- ---------------------------------------------------------------------------

CREATE TABLE oauth_client (
    id             UUID         NOT NULL,
    tenant_id      UUID         NOT NULL,
    baseline_id    UUID         NOT NULL,
    client_key     TEXT         NOT NULL,       -- external client identifier
    client_type    VARCHAR(16)  NOT NULL,       -- CONFIDENTIAL | PUBLIC
    auth_method    VARCHAR(32),                 -- MTLS | PRIVATE_KEY_JWT | CLIENT_SECRET (null for public)
    allowed_grants TEXT         NOT NULL,       -- comma-separated grant_type values
    created_at     TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_oauth_client        PRIMARY KEY (id),
    CONSTRAINT uq_oauth_client_key    UNIQUE (tenant_id, baseline_id, client_key)
);

-- ---------------------------------------------------------------------------
-- Authorization sessions (time-ordered PK — append-heavy)
-- ---------------------------------------------------------------------------

CREATE TABLE auth_session (
    id          UUID         NOT NULL,          -- UUIDv7 (time-ordered) — append-heavy table
    tenant_id   UUID         NOT NULL,
    baseline_id UUID         NOT NULL,
    subject_id  TEXT,                           -- resolved `sub`, null until the user is authenticated
    client_id   UUID,                           -- oauth_client.id this session belongs to
    state       VARCHAR(24)  NOT NULL,          -- session lifecycle state
    created_at  TIMESTAMPTZ  NOT NULL,
    expires_at  TIMESTAMPTZ,
    CONSTRAINT pk_auth_session PRIMARY KEY (id)
);

CREATE INDEX idx_auth_session_expiry ON auth_session (tenant_id, expires_at);

-- ---------------------------------------------------------------------------
-- Consents
-- ---------------------------------------------------------------------------

CREATE TABLE consent (
    id             UUID         NOT NULL,
    tenant_id      UUID         NOT NULL,
    baseline_id    UUID         NOT NULL,
    user_id        UUID         NOT NULL,
    client_id      UUID         NOT NULL,
    granted_scopes TEXT         NOT NULL,       -- space-separated scopes the user consented to
    granted_at     TIMESTAMPTZ  NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_consent        PRIMARY KEY (id),
    CONSTRAINT uq_consent_pair   UNIQUE (tenant_id, baseline_id, user_id, client_id)
);

-- ---------------------------------------------------------------------------
-- Refresh-token families (time-ordered PK — append-heavy; rotation/replay tracking)
-- ---------------------------------------------------------------------------

CREATE TABLE refresh_token_family (
    id                  UUID         NOT NULL,  -- UUIDv7 (time-ordered) — append-heavy table
    tenant_id           UUID         NOT NULL,
    baseline_id         UUID         NOT NULL,
    user_id             UUID         NOT NULL,
    client_id           UUID         NOT NULL,
    current_token_hash  TEXT         NOT NULL,  -- hash of the latest token in the family; never the token itself
    generation          INT          NOT NULL DEFAULT 0,
    reused              BOOLEAN      NOT NULL DEFAULT false, -- set true on detected replay → family revoked
    created_at          TIMESTAMPTZ  NOT NULL,
    expires_at          TIMESTAMPTZ,
    CONSTRAINT pk_refresh_token_family PRIMARY KEY (id)
);

CREATE INDEX idx_refresh_token_family_owner
    ON refresh_token_family (tenant_id, user_id, client_id);

-- ---------------------------------------------------------------------------
-- Row-level security (fail-closed) — one isolation policy per table
-- ---------------------------------------------------------------------------

ALTER TABLE iam_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_user FORCE ROW LEVEL SECURITY;
CREATE POLICY iam_user_isolation ON iam_user
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE iam_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY iam_credential_isolation ON iam_credential
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE oauth_client ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_client FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_client_isolation ON oauth_client
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE auth_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_session FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_session_isolation ON auth_session
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE consent ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent FORCE ROW LEVEL SECURITY;
CREATE POLICY consent_isolation ON consent
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE refresh_token_family ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_token_family FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_token_family_isolation ON refresh_token_family
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Table comments
-- ---------------------------------------------------------------------------

COMMENT ON TABLE iam_user IS 'End users (credential-bearing projection); RLS keyed by tenant_id.';
COMMENT ON TABLE iam_credential IS 'Verifier-side credential material (already hashed/opaque); RLS keyed by tenant_id.';
COMMENT ON TABLE oauth_client IS 'Registered OAuth2/OIDC clients; RLS keyed by tenant_id.';
COMMENT ON TABLE auth_session IS 'Authorization sessions (UUIDv7 time-ordered PK); RLS keyed by tenant_id.';
COMMENT ON TABLE consent IS 'Per-user/per-client scope consents; RLS keyed by tenant_id.';
COMMENT ON TABLE refresh_token_family IS 'Refresh-token rotation families with replay detection (UUIDv7 PK); RLS keyed by tenant_id.';
