package dev.tessera.iam.adapter.rest.authcode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.authcode.PkceMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.configuration.ConfigurationBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Proves the shared-cache authorization-code store against a real Infinispan server: the
 * multi-node property (store on one client, redeem on an independent one), consume-exactly-once
 * under genuine concurrency, fail-closed tenant scoping, and TTL expiry. Requires Docker
 * (Testcontainers); runs in CI.
 *
 * <p>Two <em>separate</em> {@link RemoteCacheManager}s stand in for two Tessera nodes. Sharing
 * one manager would prove only that a cache is a map; separate clients are what actually
 * exercises the property the in-memory store cannot provide.
 */
@DisplayName("Shared-cache authorization-code store — multi-node, exactly-once, tenant scoping, TTL (Infinispan)")
class AuthorizationCodeStoreIT {

    private static final String USER = "admin";
    private static final String PASSWORD = "password";
    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    @SuppressWarnings("resource")
    private static final GenericContainer<?> INFINISPAN =
            new GenericContainer<>(DockerImageName.parse("quay.io/infinispan/server:16.0"))
                    .withExposedPorts(11222)
                    .withEnv("USER", USER)
                    .withEnv("PASS", PASSWORD)
                    .waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(5)));

    /** The two "nodes": independent clients against the same server and cache. */
    private static RemoteCacheManager nodeA;
    private static RemoteCacheManager nodeB;

    @BeforeAll
    static void startServer() {
        INFINISPAN.start();
        nodeA = client();
        nodeB = client();
    }

    @AfterAll
    static void stopServer() {
        if (nodeA != null) {
            nodeA.stop();
        }
        if (nodeB != null) {
            nodeB.stop();
        }
        INFINISPAN.stop();
    }

    private static RemoteCacheManager client() {
        ConfigurationBuilder config = new ConfigurationBuilder();
        config.addServer()
                .host(INFINISPAN.getHost())
                .port(INFINISPAN.getMappedPort(11222))
                .security()
                .authentication()
                .username(USER)
                .password(PASSWORD);
        // Create the cache on first use rather than depending on a server-side template, so the
        // IT describes the cache the adapter actually needs.
        config.remoteCache(InfinispanAuthorizationCodeStore.CACHE_NAME)
                .configuration(
                        "{\"distributed-cache\":{\"encoding\":{\"media-type\":\"application/x-protostream\"}}}");
        return new RemoteCacheManager(config.build());
    }

    private static RemoteCache<String, String> cache(RemoteCacheManager manager) {
        return manager.getCache(InfinispanAuthorizationCodeStore.CACHE_NAME);
    }

    private static InfinispanAuthorizationCodeStore storeOn(RemoteCacheManager manager, Instant now) {
        return new InfinispanAuthorizationCodeStore(
                cache(manager), Clock.fixed(now, ZoneOffset.UTC));
    }

    private static RealmKey realm() {
        return new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(UUID.randomUUID()));
    }

    private static AuthorizationGrant grant(RealmKey realm, Instant issuedAt, Duration lifetime) {
        return new AuthorizationGrant(
                realm,
                ClientId.generate(),
                "subject-" + UUID.randomUUID(),
                "https://rp.example/callback",
                Set.of("openid", "profile"),
                "nonce-" + UUID.randomUUID(),
                new CodeChallenge(PkceMethod.S256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                issuedAt,
                issuedAt.plus(lifetime));
    }

    private static String freshCode() {
        return "code-" + UUID.randomUUID();
    }

    @Test
    @DisplayName("a code stored by one node is redeemable by an independent second node")
    void storedOnOneNodeIsRedeemableOnAnother() {
        RealmKey realm = realm();
        String code = freshCode();
        AuthorizationGrant grant = grant(realm, T0, Duration.ofMinutes(2));

        storeOn(nodeA, T0).store(code, grant).await().atMost(Duration.ofSeconds(10));

        AuthorizationGrant redeemed =
                storeOn(nodeB, T0).consume(realm, code).await().atMost(Duration.ofSeconds(10));

        // The whole grant survives the round-trip — not just "something was found". A lossy
        // field here would be a silently wrong binding check at the token endpoint.
        assertThat(redeemed).isEqualTo(grant);
    }

    @Test
    @DisplayName("concurrent redemptions of one code yield exactly one grant and the rest misses")
    void concurrentConsumeYieldsExactlyOneGrant() throws Exception {
        RealmKey realm = realm();
        String code = freshCode();
        AuthorizationGrant grant = grant(realm, T0, Duration.ofMinutes(2));
        storeOn(nodeA, T0).store(code, grant).await().atMost(Duration.ofSeconds(10));

        int attempts = 8;
        // Half the redemptions go through each node, so the race is across clients too.
        InfinispanAuthorizationCodeStore a = storeOn(nodeA, T0);
        InfinispanAuthorizationCodeStore b = storeOn(nodeB, T0);

        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        try {
            List<Callable<AuthorizationGrant>> redemptions = new java.util.ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                InfinispanAuthorizationCodeStore store = (i % 2 == 0) ? a : b;
                redemptions.add(() -> store.consume(realm, code).await().atMost(Duration.ofSeconds(10)));
            }
            List<Future<AuthorizationGrant>> results = pool.invokeAll(redemptions);

            long granted = 0;
            for (Future<AuthorizationGrant> result : results) {
                if (result.get() != null) {
                    granted++;
                }
            }
            // This is the single replay defence: one winner, no exceptions.
            assertThat(granted).isEqualTo(1);
        } finally {
            pool.shutdownNow();
            assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    @DisplayName("a code stored under one realm is a miss under another")
    void codeIsNotVisibleAcrossRealms() {
        RealmKey realmA = realm();
        RealmKey realmB = realm();
        String code = freshCode();
        storeOn(nodeA, T0)
                .store(code, grant(realmA, T0, Duration.ofMinutes(2)))
                .await()
                .atMost(Duration.ofSeconds(10));

        AuthorizationGrant crossTenant =
                storeOn(nodeB, T0).consume(realmB, code).await().atMost(Duration.ofSeconds(10));
        assertThat(crossTenant).isNull();

        // ...and the failed cross-tenant attempt did not consume the real entry.
        AuthorizationGrant owner =
                storeOn(nodeB, T0).consume(realmA, code).await().atMost(Duration.ofSeconds(10));
        assertThat(owner).isNotNull();
    }

    @Test
    @DisplayName("a code is a miss once its TTL has elapsed")
    void codeExpires() {
        RealmKey realm = realm();
        String code = freshCode();
        // A 1-second lifetime keeps the test honest (a real server-side expiry) and quick.
        storeOn(nodeA, T0)
                .store(code, grant(realm, T0, Duration.ofSeconds(1)))
                .await()
                .atMost(Duration.ofSeconds(10));

        // Read back with a clock past the expiry: the entry is gone server-side, and even if the
        // server had not swept it yet, consume re-checks expiry, so this is a miss either way.
        AuthorizationGrant expired = storeOn(nodeB, T0.plusSeconds(5))
                .consume(realm, code)
                .await()
                .atMost(Duration.ofSeconds(10));
        assertThat(expired).isNull();
    }

    @Test
    @DisplayName("an already-expired grant is refused rather than stored without a lifespan")
    void refusesToStoreAnExpiredGrant() {
        RealmKey realm = realm();
        InfinispanAuthorizationCodeStore store = storeOn(nodeA, T0.plusSeconds(600));

        // Infinispan reads a non-positive lifespan as "use the default" (and -1 as immortal), so
        // storing an expired grant would outlive the code it stands for. It must be refused.
        assertThatThrownBy(() -> store.store(freshCode(), grant(realm, T0, Duration.ofMinutes(2))))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
