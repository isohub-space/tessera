package dev.tessera.iam.adapter.rest.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.RefreshTokenStorePort.RefreshConsumeOutcome;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("InMemoryRefreshTokenStore — atomic single-use rotation, replay burns the family")
class InMemoryRefreshTokenStoreTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());

    private RefreshTokenFamily seed(InMemoryRefreshTokenStore store, String currentHash) {
        RefreshTokenFamily fam = new RefreshTokenFamily(
                new FamilyId(UUID.randomUUID()), REALM, "user-1", ClientId.generate(),
                currentHash, null, 0, false, NOW, NOW.plusSeconds(3600));
        store.createFamily(fam).await().indefinitely();
        return fam;
    }

    @Test
    @DisplayName("presenting the current token rotates; re-presenting it is a replay that burns the family")
    void rotateThenReplay() {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        RefreshTokenFamily fam = seed(store, "h0");

        RefreshConsumeOutcome first =
                store.consumeAndRotate(fam.id(), REALM, "h0", "h1", NOW).await().indefinitely();
        assertThat(first.decision()).isInstanceOf(RefreshDecision.Rotate.class);
        assertThat(first.family().currentTokenHash()).isEqualTo("h1");
        assertThat(first.family().previousTokenHash()).isEqualTo("h0");
        assertThat(first.family().generation()).isEqualTo(1);

        // Re-presenting the now-superseded h0 is the canonical replay → family burned.
        RefreshConsumeOutcome replay =
                store.consumeAndRotate(fam.id(), REALM, "h0", "h2", NOW).await().indefinitely();
        assertThat(replay.decision()).isInstanceOf(RefreshDecision.Replay.class);

        // Once burned, even the legitimate current token (h1) is refused.
        RefreshConsumeOutcome afterBurn =
                store.consumeAndRotate(fam.id(), REALM, "h1", "h3", NOW).await().indefinitely();
        assertThat(afterBurn.decision()).isInstanceOf(RefreshDecision.Replay.class);
    }

    @Test
    @DisplayName("a wrong-realm redemption never sees the family (RLS parity → Unknown)")
    void wrongRealmIsUnknown() {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        RefreshTokenFamily fam = seed(store, "h0");
        RealmKey other = new RealmKey(TenantId.generate(), BaselineId.generate());

        RefreshConsumeOutcome outcome =
                store.consumeAndRotate(fam.id(), other, "h0", "h1", NOW).await().indefinitely();
        assertThat(outcome.decision()).isInstanceOf(RefreshDecision.Unknown.class);
        // find is realm-scoped; the resolver is header-independent.
        assertThat(store.find(fam.id(), other).await().indefinitely()).isNull();
        assertThat(store.resolveOwningRealm(fam.id()).await().indefinitely()).contains(REALM);
    }

    @Test
    @DisplayName("revokeFamily is idempotent")
    void revokeIdempotent() {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        RefreshTokenFamily fam = seed(store, "h0");
        store.revokeFamily(fam.id(), REALM).await().indefinitely();
        store.revokeFamily(fam.id(), REALM).await().indefinitely();
        assertThat(store.consumeAndRotate(fam.id(), REALM, "h0", "h1", NOW).await().indefinitely()
                .decision()).isInstanceOf(RefreshDecision.Replay.class);
    }

    @Test
    @DisplayName("concurrent redemptions of the same token yield exactly one Rotate")
    void concurrentRotateIsSingleUse() throws Exception {
        InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
        RefreshTokenFamily fam = seed(store, "h0");

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<RefreshConsumeOutcome>> tasks = java.util.Collections.nCopies(threads,
                    () -> store.consumeAndRotate(fam.id(), REALM, "h0", "h-new", NOW)
                            .await().indefinitely());
            long rotates = pool.invokeAll(tasks).stream()
                    .map(InMemoryRefreshTokenStoreTest::get)
                    .filter(o -> o.decision() instanceof RefreshDecision.Rotate)
                    .count();
            assertThat(rotates).isEqualTo(1L);
        } finally {
            pool.shutdownNow();
        }
    }

    private static RefreshConsumeOutcome get(Future<RefreshConsumeOutcome> f) {
        try {
            return f.get();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
