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
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The pooled connection's network path dies while the pool still holds it (what a NAT or firewall
 * idle cut-off does), then the next request borrows it.
 *
 * <p>When the connection fails before a unit of work's own statements go out (it begins its
 * transaction and binds the tenant first), the unit runs again on a fresh connection within the same
 * call, read or write; nothing of it had been sent. When the connection fails after its statements
 * went out, the unit fails, is not retried and leaves no trace. The after-start cases cover the
 * refresh-token operations whose double application would matter (family creation, rotation,
 * revocation): each fails here if the retry window is ever widened past the start of the work,
 * because the retry would make the call succeed.
 *
 * <p>The acquisition cases hold the pool's only connection, so a request gets none within the 2 s
 * acquisition timeout.
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

    @Inject
    Pool pool;

    @Inject
    PoolDiagnostics diagnostics;

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

    /** Warms the single pooled connection with a read, then kills its network path at once. */
    private void warmThenDoom(UniAsserter asserter, UUID tenant) {
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                warm -> assertThat(warm).isNull());
        asserter.execute(() -> assertThat(doomPooledConnections()).isEqualTo(1));
    }

    /**
     * Warms the single pooled connection, then kills its network path when the first statement
     * naming {@code table} goes out: after the transaction began and the tenant was bound, that is
     * once the unit's own work has started.
     */
    private void warmThenDoomOnceWorkStarts(UniAsserter asserter, UUID tenant, String table) {
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                warm -> assertThat(warm).isNull());
        asserter.execute(() -> assertThat(Integer.parseInt(ResettingTcpProxy.command(adminPort, "doom-on " + table)))
                .isEqualTo(1));
    }

    private static <T> void assertConnectionFailure(UniAsserter asserter, Supplier<Uni<T>> write) {
        asserter.assertFailedWith(write,
                failure -> assertThat(ConnectionFailures.isConnectionFailure(failure))
                        .as("the write surfaces the connection failure instead of retrying: %s", failure)
                        .isTrue());
    }

    /**
     * Takes the pool's only connection and keeps it busy for {@code seconds}, so requests in the
     * meantime wait for a connection. Completes once the connection is held; {@code released}
     * completes when it is back in the pool.
     */
    private Uni<Void> holdTheOnlyConnection(double seconds, CompletableFuture<Void> released) {
        return Uni.createFrom().completionStage(pool.getConnection()
                .onSuccess(conn -> conn.query("select pg_sleep(" + seconds + ")").execute()
                        .onComplete(done -> conn.close().onComplete(closed -> released.complete(null))))
                .mapEmpty()
                .toCompletionStage())
                .replaceWithVoid();
    }

    /** A second create of the same family must fail on its primary key, not on the connection. */
    private static <T> void assertConnectionFailureFree(UniAsserter asserter, Supplier<Uni<T>> duplicate) {
        asserter.assertFailedWith(duplicate,
                failure -> assertThat(ConnectionFailures.isRetryableBeforeWork(failure))
                        .as("a constraint violation, not a connection problem: %s", failure).isFalse());
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
            assertThat(options.getConnectTimeout()).isEqualTo(1_000);
        });
        PoolOptions poolOptions = poolCreator.configuredPoolOptions();
        assertThat(poolOptions.getConnectionTimeoutUnit().toMillis(poolOptions.getConnectionTimeout()))
                .isEqualTo(2_000);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the pool's new connections pass through the diagnostics and are handed over")
    void diagnosticsSeeNewConnections(UniAsserter asserter) {
        asserter.assertThat(() -> users.findById(UUID.randomUUID(), UUID.randomUUID()),
                found -> assertThat(found).isNull());
        asserter.execute(() -> {
            assertThat(diagnostics.attemptsStarted()).isPositive();
            assertThat(diagnostics.connectionsOpened()).isPositive();
            assertThat(diagnostics.state()).contains("of 1 open");
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
    @DisplayName("a read that gets no connection within the acquisition timeout waits once more and succeeds")
    void readRetriesAfterAcquisitionTimeout(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        CompletableFuture<Void> released = new CompletableFuture<>();

        asserter.execute(() -> holdTheOnlyConnection(3, released));
        // The first wait ends at 2 s with the acquisition timeout; the retry gets the connection at 3 s.
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()), found -> assertThat(found).isNull());
        asserter.execute(() -> Uni.createFrom().completionStage(released));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a write that gets no connection within the acquisition timeout runs once, on the retry")
    void writeRetriesAfterAcquisitionTimeout(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());
        CompletableFuture<Void> released = new CompletableFuture<>();

        asserter.execute(() -> holdTheOnlyConnection(3, released));
        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        asserter.assertThat(() -> refreshTokens.find(fid, realm(tenant)),
                found -> assertThat(found).as("the family was written").isNotNull());
        // Applying it twice would have failed on the primary key; a second create proves it is there once.
        assertConnectionFailureFree(asserter, () -> refreshTokens.createFamily(family(fid, realm(tenant))));
        asserter.execute(() -> Uni.createFrom().completionStage(released));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the acquisition-timeout retry is bounded: a connection held past both waits fails the read")
    void acquisitionRetryIsBounded(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        CompletableFuture<Void> released = new CompletableFuture<>();

        asserter.execute(() -> holdTheOnlyConnection(5, released));
        asserter.assertFailedWith(() -> users.findById(tenant, UUID.randomUUID()),
                failure -> assertThat(ConnectionFailures.isAcquisitionTimeout(failure))
                        .as("two waits of 2 s each, then the timeout surfaces: %s", failure).isTrue());
        asserter.execute(() -> Uni.createFrom().completionStage(released));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a write whose connection fails before its statements go out runs again, once")
    void writeFailingBeforeItStartsIsRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        warmThenDoom(asserter, tenant);
        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        asserter.assertThat(() -> refreshTokens.find(fid, realm(tenant)),
                found -> assertThat(found).as("the family was written").isNotNull());
        // Applying it twice would have failed on the primary key; a second create proves it is there once.
        assertConnectionFailureFree(asserter, () -> refreshTokens.createFamily(family(fid, realm(tenant))));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a session state write whose connection fails after it started is not retried")
    void sessionWriteIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();

        warmThenDoomOnceWorkStarts(asserter, tenant, "auth_session");
        assertConnectionFailure(asserter, () -> authSessions.updateState(tenant, UUID.randomUUID(), "ENDED"));
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                found -> assertThat(found).as("the next read works").isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token family creation whose connection fails after it started is not retried and creates nothing")
    void familyCreationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        warmThenDoomOnceWorkStarts(asserter, tenant, "refresh_token_family");
        assertConnectionFailure(asserter, () -> refreshTokens.createFamily(family(fid, realm(tenant))));
        asserter.assertThat(() -> refreshTokens.find(fid, realm(tenant)),
                found -> assertThat(found).as("no family was written").isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token rotation whose connection fails after it started is not retried and rotates nothing")
    void rotationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        warmThenDoomOnceWorkStarts(asserter, tenant, "refresh_token_family");
        assertConnectionFailure(asserter,
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(60)));
        // Had the failed call rotated (h0 -> h1), presenting h0 again would be a replay.
        asserter.assertThat(
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(61)),
                outcome -> assertThat(outcome.decision()).isInstanceOf(RefreshDecision.Rotate.class));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("refresh-token family revocation whose connection fails after it started is not retried and revokes nothing")
    void revocationIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        FamilyId fid = new FamilyId(UUID.randomUUID());

        asserter.execute(() -> refreshTokens.createFamily(family(fid, realm(tenant))));
        warmThenDoomOnceWorkStarts(asserter, tenant, "refresh_token_family");
        assertConnectionFailure(asserter, () -> refreshTokens.revokeFamily(fid, realm(tenant)));
        asserter.assertThat(
                () -> refreshTokens.consumeAndRotate(fid, realm(tenant), "h0", "h1", T0.plusSeconds(60)),
                outcome -> assertThat(outcome.decision()).as("the family is still live")
                        .isInstanceOf(RefreshDecision.Rotate.class));
    }
}
