package dev.tessera.iam.adapter.persistence.db;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.persistence.repository.AuthSessionRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The pooled connection's network path dies while the pool still holds it (what a NAT or firewall
 * idle cut-off does), then the next request borrows it.
 *
 * <p>A read recovers on a fresh connection within the same call. A write is not retried: it fails,
 * leaves no trace, and the request after it works again because the dead connection has left the
 * pool. The write cases cover the refresh-token operations whose double application would matter
 * (family creation, rotation, revocation): each fails here if it is ever moved to the retrying read
 * path, because the retry would make the call succeed.
 */
@QuarkusTest
@TestProfile(ResettingProxyProfile.class)
@DisplayName("Database connection reset by the network path (PostgreSQL integration)")
class ConnectionResetRecoveryIT {

    @Inject
    UserRepository users;

    @Inject
    AuthSessionRepository authSessions;

    @Inject
    RefreshTokenStorePort refreshTokens;

    @Inject
    TesseraPgPoolCreator poolCreator;

    @ConfigProperty(name = ResettingProxyPostgresResource.ADMIN_PORT)
    int adminPort;

    private int doomPooledConnections() {
        return Integer.parseInt(ResettingTcpProxy.command(adminPort, "doom"));
    }

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    private static RealmKey realm(UUID tenant) {
        return new RealmKey(new TenantId(tenant), new BaselineId(new UUID(0L, 0L)));
    }

    private static RefreshTokenFamily family(FamilyId id, RealmKey realm) {
        return new RefreshTokenFamily(
                id, realm, UUID.randomUUID().toString(), ClientId.generate(),
                "h0", null, 0, false, T0, T0.plusSeconds(3600));
    }

    /** Warms the single pooled connection with a read, then kills its network path. */
    private void warmThenDoom(UniAsserter asserter, UUID tenant) {
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                warm -> assertThat(warm).isNull());
        asserter.execute(() -> assertThat(doomPooledConnections()).isEqualTo(1));
    }

    private static <T> void assertConnectionFailure(UniAsserter asserter, Supplier<Uni<T>> write) {
        asserter.assertFailedWith(write,
                failure -> assertThat(ConnectionFailures.isConnectionFailure(failure))
                        .as("the write surfaces the connection failure instead of retrying: %s", failure)
                        .isTrue());
    }

    private int resetsSoFar() {
        return Integer.parseInt(ResettingTcpProxy.command(adminPort, "resets"));
    }

    @Test
    @DisplayName("Quarkus built the pool through the creator, with the socket options on its connect options")
    void poolCarriesSocketOptions() {
        assertThat(poolCreator.configuredOptions()).as("the creator built the runtime pool").isNotEmpty();
        assertThat(poolCreator.configuredOptions()).allSatisfy(options -> {
            assertThat(options.getTcpUserTimeout()).isEqualTo(5_000);
            assertThat(options.isTcpKeepAlive()).isTrue();
            assertThat(options.getTcpKeepAliveIdleSeconds()).isEqualTo(30);
            assertThat(options.getTcpKeepAliveIntervalSeconds()).isEqualTo(10);
            assertThat(options.getTcpKeepAliveCount()).isEqualTo(3);
        });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a read on a reset pooled connection succeeds on a fresh one")
    void readRecoversAfterReset(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        AtomicInteger resetsBefore = new AtomicInteger();

        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                warm -> assertThat(warm).isNull());
        asserter.execute(() -> {
            resetsBefore.set(resetsSoFar());
            assertThat(doomPooledConnections()).as("the warm connection is in the pool").isEqualTo(1);
        });
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                found -> assertThat(found).isNull());
        asserter.execute(() -> assertThat(resetsSoFar() - resetsBefore.get())
                .as("the read really met the reset before it recovered").isEqualTo(1));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a session state write on a reset pooled connection fails and is not retried")
    void sessionWriteIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();

        warmThenDoom(asserter, tenant);
        assertConnectionFailure(asserter, () -> authSessions.updateState(tenant, UUID.randomUUID(), "ENDED"));
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                found -> assertThat(found).as("the dead connection left the pool").isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token family creation on a reset connection fails, is not retried and creates nothing")
    void familyCreationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        warmThenDoom(asserter, tenant);
        assertConnectionFailure(asserter, () -> refreshTokens.createFamily(family(fid, realm(tenant))));
        asserter.assertThat(() -> refreshTokens.find(fid, realm(tenant)),
                found -> assertThat(found).as("no family was written").isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token rotation on a reset connection fails, is not retried and rotates nothing")
    void rotationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        warmThenDoom(asserter, tenant);
        assertConnectionFailure(asserter,
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(60)));
        // Had the failed call rotated (h0 -> h1), presenting h0 again would be a replay.
        asserter.assertThat(
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(61)),
                outcome -> assertThat(outcome.decision()).isInstanceOf(RefreshDecision.Rotate.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token family revocation on a reset connection fails, is not retried and revokes nothing")
    void revocationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        warmThenDoom(asserter, tenant);
        assertConnectionFailure(asserter, () -> refreshTokens.revokeFamily(fid, realm(tenant)));
        asserter.assertThat(
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(60)),
                outcome -> assertThat(outcome.decision()).as("the family is still live")
                        .isInstanceOf(RefreshDecision.Rotate.class));
    }
}
