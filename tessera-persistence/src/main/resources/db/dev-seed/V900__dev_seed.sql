- dev-only seed.
--
-- Runs ONLY under the %dev profile, via the extra Flyway location
-- `%dev.quarkus.flyway.locations=db/migration,db/dev-seed`. It is NOT on the
-- classpath location list used by %test, so the no-cross-tenant-leakage IT keeps
-- creating its own tenants and asserting fail-closed isolation against an otherwise
-- empty table.
--
-- It seeds the fixed well-known dev tenant (see DevTenant.ID) with one ACTIVE
-- signing key so `GET /q/health/ready` is UP under `quarkus dev`.
--
-- signing_key has FORCE ROW LEVEL SECURITY, so even this seed must bind a tenant
-- before it can INSERT: set the GUC for the dev tenant (transaction-local, third arg
-- false here = session level, which is fine for a one-off migration connection) and
-- the WITH CHECK policy then accepts the matching tenant_id row.
SELECT set_config('app.tenant_id', '0de00000-0000-4000-a000-00000000d3f0', false);

INSERT INTO signing_key (id, tenant_id, kid, algorithm, state, public_jwk, created_at)
VALUES (
    '0de00000-0000-4000-a000-00000000515e',
    '0de00000-0000-4000-a000-00000000d3f0',   -- DevTenant.ID
    'dev-key-1',
    'EdDSA',
    'ACTIVE',
    '{"kty":"OKP","crv":"Ed25519","x":"dev-placeholder-public-key"}',
    now()
);
