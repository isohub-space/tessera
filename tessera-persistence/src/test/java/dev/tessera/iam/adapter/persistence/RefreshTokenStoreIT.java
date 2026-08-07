package dev.tessera.iam.adapter.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the DB-backed refresh-token family store against real PostgreSQL: single-use rotation via
 * the conditional compare-and-swap, replay detection that burns the whole family, fail-closed
 * row-level-security isolation between tenants, isolation between baselines <em>within</em> one
 * tenant (which RLS alone does not provide, since it binds {@code app.tenant_id} only), and the
 * header-independent tenant resolver backed by the (deliberately un-scoped) family directory.
 * Requires Docker (Testcontainers); runs in CI.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("DB refresh-token family store — CAS rotation, replay, RLS, tenant resolver (PostgreSQL)")
class RefreshTokenStoreIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");
    private static final Instant NOW = T0.plusSeconds(60);

    @Inject
    RefreshTokenStorePort store;

    @Inject
    RefreshTokenTenantResolverPort resolver;

    private static RealmKey realm(UUID tenantId) {
        return realm(tenantId, new UUID(0L, 0L));
    }

    private static RealmKey realm(UUID tenantId, UUID baselineId) {
        return new RealmKey(new TenantId(tenantId), new BaselineId(baselineId));
    }

    private static RefreshTokenFamily family(FamilyId id, RealmKey realm, String currentHash) {
        return new RefreshTokenFamily(
                id, realm, UUID.randomUUID().toString(), ClientId.generate(),
                currentHash, null, 0, false, T0, T0.plusSeconds(3600));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("rotates on the current token; a replayed superseded token burns the whole family")
    void rotatesAndDetectsReplay(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> store.createFamily(family(fid, realm(tenant), "h0")));

        // Presenting the current token rotates the family forward (h0 -> h1).
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Rotate.class));

        // Re-presenting the now-superseded h0 is a replay: the whole family is revoked.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "h0", "h2", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Replay.class));

        // Once burned, even the legitimate current token h1 is refused.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "h1", "h3", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Replay.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("RLS isolates families: a redemption scoped to another tenant never sees the family")
    void rlsIsolation(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> store.createFamily(family(fid, realm(tenantA), "h0")));

        // Scoped to tenant B, tenant A's family is invisible (RLS) → Unknown, and A's row is NOT
        // burned by the wrong-tenant probe.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenantB), "h0", "hx", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Unknown.class));
        asserter.assertThat(
                () -> store.find(fid, realm(tenantB)),
                fam -> assertThat(fam).isNull());
        // Under A it is still live and rotates.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenantA), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Rotate.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the directory resolves a family's owning realm header-independently; unknown → empty")
    void tenantResolver(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());
        asserter.execute(() -> store.createFamily(family(fid, realm(tenant), "h0")));

        // Resolved with no tenant bound — the authoritative realm comes from the directory.
        asserter.assertThat(
                () -> resolver.resolveOwningRealm(fid),
                owner -> assertThat(owner).contains(realm(tenant)));
        asserter.assertThat(
                () -> resolver.resolveOwningRealm(new FamilyId(UUID.randomUUID())),
                owner -> assertThat(owner).isEmpty());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a stranger hash against a live family is Unknown and does not burn it")
    void strangerHashDoesNotBurn(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());
        asserter.execute(() -> store.createFamily(family(fid, realm(tenant), "h0")));

        // A forged token must be rejected without revoking the family (revocation-DoS guard).
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "stranger", "hx", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Unknown.class));
        // The genuine current token still rotates, proving the family stayed live.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Rotate.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("revokeFamily is idempotent and burns the family")
    void revokeIsIdempotent(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());
        asserter.execute(() -> store.createFamily(family(fid, realm(tenant), "h0")));

        asserter.execute(() -> store.revokeFamily(fid, realm(tenant)));
        asserter.execute(() -> store.revokeFamily(fid, realm(tenant)));
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Replay.class));
    }

    // -------------------------------------------------------------------------
    // Baseline isolation — the axis RLS does NOT cover.
    //
    // RLS binds app.tenant_id only, so for two baselines under ONE tenant the database
    // happily returns the other baseline's row: nothing but an explicit baseline predicate
    // can exclude it. These mirror rlsIsolation() above, varying baseline instead of tenant.
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("baseline isolation: a same-tenant family in another baseline is invisible to find()")
    void findIsScopedByBaselineNotOnlyTenant(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baselineA = UUID.randomUUID();
        UUID baselineB = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> store.createFamily(family(fid, realm(tenant, baselineA), "h0")));

        // Same tenant, other baseline: invisible. Fails pre-fix, where the bare PK lookup
        // cleared RLS's tenant scope and returned the family.
        asserter.assertThat(
                () -> store.find(fid, realm(tenant, baselineB)),
                fam -> assertThat(fam).isNull());

        // Counter-check: under its OWN realm the family is still found, and the snapshot
        // carries the row's own realm. Without this, the assertion above would pass just as
        // well against a find() broken into returning null for every caller.
        asserter.assertThat(
                () -> store.find(fid, realm(tenant, baselineA)),
                fam -> {
                    assertThat(fam).isNotNull();
                    assertThat(fam.realm()).isEqualTo(realm(tenant, baselineA));
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("baseline isolation: revokeFamily from another baseline in the same tenant does not burn it")
    void revokeFamilyIsScopedByBaselineNotOnlyTenant(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baselineA = UUID.randomUUID();
        UUID baselineB = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> store.createFamily(family(fid, realm(tenant, baselineA), "h0")));

        // revokeFamily returns Uni<Void> either way, so the call proves nothing on its own —
        // the burn is observable only through the family's subsequent liveness.
        asserter.execute(() -> store.revokeFamily(fid, realm(tenant, baselineB)));

        // Unaffected: the genuine current token still rotates under the owning realm. Fails
        // pre-fix, where BURN matched on id alone, leaving reused = true and yielding Replay.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant, baselineA), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Rotate.class));

        // Counter-check: the OWNING baseline's revoke must still burn. Without this the
        // assertion above would also pass against a revokeFamily() broken into a no-op for
        // everyone — a "fix" that satisfies the AC by disabling revocation entirely.
        asserter.execute(() -> store.revokeFamily(fid, realm(tenant, baselineA)));
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant, baselineA), "h1", "h2", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Replay.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("baseline isolation: a redemption from another baseline is Unknown and neither rotates nor burns")
    void consumeAndRotateIsScopedByBaselineNotOnlyTenant(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID baselineA = UUID.randomUUID();
        UUID baselineB = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> store.createFamily(family(fid, realm(tenant, baselineA), "h0")));

        // Presenting A's genuine current token from baseline B must not redeem it. Fails
        // pre-fix, where CAS_ROTATE matched on id + hash alone and handed baseline B a Rotate.
        // The family snapshot must be withheld too: the row IS RLS-visible here (same tenant),
        // so returning it would let baseline B read A's token hashes, generation and client,
        // and tell "no such family" apart from "family in a sibling baseline".
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant, baselineB), "h0", "hx", NOW),
                o -> {
                    assertThat(o.decision()).isInstanceOf(RefreshDecision.Unknown.class);
                    assertThat(o.family()).isNull();
                });

        // Neither rotated nor burned by that attempt: h0 is still the live current token
        // under the owning realm. Pre-fix this came back Replay, because B's redemption had
        // already rotated h0 into previous_token_hash.
        asserter.assertThat(
                () -> store.consumeAndRotate(fid, realm(tenant, baselineA), "h0", "h1", NOW),
                o -> assertThat(o.decision()).isInstanceOf(RefreshDecision.Rotate.class));
    }
}
