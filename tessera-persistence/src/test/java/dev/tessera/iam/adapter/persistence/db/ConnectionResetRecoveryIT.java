package dev.tessera.iam.adapter.persistence.db;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.persistence.repository.AuthSessionRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import jakarta.inject.Inject;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The pooled connection's network path dies while the pool still holds it (what a NAT or firewall
 * idle cut-off does), then the next request borrows it.
 *
 * <p>A read recovers on a fresh connection within the same call. A write is not retried: it fails,
 * and the request after it works again because the dead connection has left the pool.
 */
@QuarkusTest
@TestProfile(ResettingProxyProfile.class)
@DisplayName("Database connection reset by the network path (PostgreSQL integration)")
class ConnectionResetRecoveryIT {

    @Inject
    UserRepository users;

    @Inject
    AuthSessionRepository authSessions;

    @ConfigProperty(name = ResettingProxyPostgresResource.ADMIN_PORT)
    int adminPort;

    private int doomPooledConnections() {
        return Integer.parseInt(ResettingTcpProxy.command(adminPort, "doom"));
    }

    private int resetsSoFar() {
        return Integer.parseInt(ResettingTcpProxy.command(adminPort, "resets"));
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
    @DisplayName("a write on a reset pooled connection fails and is not retried")
    void writeIsNotRetried(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();

        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                warm -> assertThat(warm).isNull());
        asserter.execute(() -> assertThat(doomPooledConnections()).isEqualTo(1));
        asserter.assertFailedWith(() -> authSessions.updateState(tenant, UUID.randomUUID(), "ENDED"),
                failure -> assertThat(ConnectionFailures.isConnectionFailure(failure))
                        .as("the write surfaces the connection failure: %s", failure).isTrue());
        asserter.assertThat(() -> users.findById(tenant, UUID.randomUUID()),
                found -> assertThat(found).as("the dead connection left the pool").isNull());
    }
}
