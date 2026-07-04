-- V6 — refresh-token rotation: previous-token hash + revocation columns, a rotation
-- fast-path index, and a header-independent family→tenant directory.
--
-- Single-use rotation with replay detection (OAuth 2.0 Security BCP / RFC 9700 §4.14):
-- each redemption issues a fresh token, invalidates the presented one, and advances the
-- family. Presenting a superseded token (now previous_token_hash) or an already-revoked
-- family is a replay that revokes the whole lineage.

ALTER TABLE refresh_token_family
    ADD COLUMN previous_token_hash TEXT,
    ADD COLUMN revoked_at          TIMESTAMPTZ;

COMMENT ON COLUMN refresh_token_family.previous_token_hash IS
    'Hash of the immediately superseded token (NULL at generation 0); presenting it is a replay signal.';
COMMENT ON COLUMN refresh_token_family.revoked_at IS
    'When the family was revoked (replay detected or explicit revocation); NULL while live.';

-- (No new index: every rotation/lookup keys on the primary key — the family id is embedded in
-- the token — so the existing PK index serves them. The refresh_token_family RLS policy (V3) is
-- table-level and already governs the new columns.)

-- ---------------------------------------------------------------------------
-- Family → owning-tenant directory
-- ---------------------------------------------------------------------------
-- DELIBERATELY NOT tenant-scoped (no row-level security). This table IS the mechanism that
-- resolves a presented refresh token's AUTHORITATIVE tenant WITHOUT trusting the request
-- header, so a replayed or stolen token is detected — and its family revoked — even when the
-- caller sends a wrong or absent tenant header. Scoping it by tenant would be circular: it is
-- what resolves the tenant. It holds ONLY (opaque random family_id → tenant_id, baseline_id) —
-- never token material, user, or scope — so its blast radius is narrow: a party with direct
-- app-role database access (already a full compromise) could map a known family UUID to its
-- tenant.
--
-- A SECURITY DEFINER bypass function was rejected: FORCE ROW LEVEL SECURITY binds even the
-- table owner (iam_migrator), and migrations run as a non-superuser role, so no BYPASSRLS role
-- can be created here — a definer function would itself see zero rows. A plain un-scoped table
-- read is the correct, role-model-compatible resolver.
CREATE TABLE refresh_family_directory (
    family_id   UUID NOT NULL,
    tenant_id   UUID NOT NULL,
    baseline_id UUID NOT NULL,
    CONSTRAINT pk_refresh_family_directory PRIMARY KEY (family_id)
);

COMMENT ON TABLE refresh_family_directory IS
    'Header-independent family->tenant resolver source for refresh-token reuse-detection; intentionally not tenant-scoped (see V6 header).';
