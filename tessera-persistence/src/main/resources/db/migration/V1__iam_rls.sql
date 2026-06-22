-- V1 — signing-key schema + PostgreSQL row-level security.
-- This is the first IAM slice: a single tenant-scoped `signing_key` table backing
-- the signing-key readiness gate. Domain models for clients and tokens
-- arrive in later migrations; request-scoped X-Tenant-Id REST propagation is wired in the REST adapter.
--
-- RLS idiom: every tenant-scoped table is
-- keyed by `tenant_id` and protected by a policy comparing it to the per-transaction
-- GUC `app.tenant_id`, set via `set_config('app.tenant_id', <uuid>, true)` at the
-- start of each transaction. `current_setting('app.tenant_id', true)` returns NULL
-- (or, on a pooled connection where the GUC was previously set LOCAL, an empty
-- string) when no tenant is bound; `NULLIF(..., '')::uuid` normalises both to NULL,
-- so the predicate evaluates to NULL → the row is invisible and writes are rejected:
-- the schema FAILS CLOSED when no tenant is bound. FORCE ROW LEVEL SECURITY makes the
-- policies apply even to the table owner (iam_migrator).

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

CREATE TABLE signing_key (
    id          UUID         NOT NULL,
    tenant_id   UUID         NOT NULL,
    kid         TEXT         NOT NULL,          -- JWK key id
    algorithm   TEXT         NOT NULL,          -- e.g. 'EdDSA'
    state       VARCHAR(16)  NOT NULL,          -- PENDING | ACTIVE | RETIRING | RETIRED
    public_jwk  TEXT         NOT NULL,          -- serialized public JWK
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_signing_key      PRIMARY KEY (id),
    CONSTRAINT uq_signing_key_kid  UNIQUE (tenant_id, kid)
);

-- Tenant-scoped lookup index (readiness gate filters by tenant + state).
CREATE INDEX idx_signing_key_tenant ON signing_key (tenant_id);

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

ALTER TABLE signing_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_key FORCE ROW LEVEL SECURITY;
CREATE POLICY signing_key_isolation ON signing_key
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- ---------------------------------------------------------------------------
-- Least-privilege role model
-- ---------------------------------------------------------------------------
-- THREE roles, none of which is a superuser at runtime — a superuser bypasses RLS
-- unconditionally, defeating FORCE ROW LEVEL SECURITY:
--   * iam_migrator — Flyway connects as this NON-superuser role, so every table
--     created by this migration is OWNED by iam_migrator (not the cluster
--     superuser). FORCE ROW LEVEL SECURITY then binds even the owner.
--   * iam_app      — the runtime datasource role; owns nothing, holds only DML.
--     RLS is enforced against it.
--   * cluster superuser — used by neither at runtime; only to CREATE the two roles
--     and grant iam_migrator CREATE (done out-of-band / by the Testcontainers init
--     script / Dev Services).
-- This migration runs AS iam_migrator and grants the app role its DML. The grant is
-- guarded so the migration stays portable to environments where the role is
-- provisioned out-of-band (infra), named differently, or where Dev Services runs the
-- whole thing as one superuser (the guard simply no-ops). ALTER DEFAULT PRIVILEGES
-- ensures tables added by iam_migrator in later migrations also grant iam_app
-- automatically.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'iam_app') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO iam_app';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iam_app';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
              || 'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app';
    END IF;
END $$;

COMMENT ON TABLE signing_key IS 'Tenant signing keys (OIDC/OAuth2); RLS keyed by tenant_id..';
