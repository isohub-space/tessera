// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.infinispan.client.hotrod.RemoteCache;
import org.infinispan.client.hotrod.RemoteCacheManager;
import org.infinispan.client.hotrod.configuration.ConfigurationBuilder;
import org.infinispan.commons.IllegalLifecycleStateException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * Proves the shared store of requests waiting for sign-in against a real Infinispan server: a
 * sign-in started on one node finishes on another with the request intact, it is answered at
 * most once under concurrent posts, it is invisible to another realm, and it expires. Two
 * separate clients stand in for two tessera nodes, as in {@code AuthorizationCodeStoreIT}.
 * Requires Docker (Testcontainers).
 */
@DisplayName("Shared pending-sign-in store — multi-node, exactly-once, tenant scoping, TTL (Infinispan)")
class PendingAuthorizationStoreIT {

    private static final String USER = "admin";
    private static final String PASSWORD = "password";
    private static final Instant T0 = Instant.parse("2026-10-26T08:00:00Z");
    private static final Duration WAIT = Duration.ofSeconds(10);

    @SuppressWarnings("resource")
    private static final GenericContainer<?> INFINISPAN =
            new GenericContainer<>(DockerImageName.parse("quay.io/infinispan/server:16.0"))
                    .withExposedPorts(11222)
                    .withEnv("USER", USER)
                    .withEnv("PASS", PASSWORD)
                    .waitingFor(Wait.forLogMessage(".*Infinispan Server.*started in.*\\n", 1)
                            .withStartupTimeout(Duration.ofMinutes(5)));

    private static RemoteCacheManager nodeA;
    private static RemoteCacheManager nodeB;
    private static RemoteCache<String, String> cacheA;
    private static RemoteCache<String, String> cacheB;

    @BeforeAll
    static void startServer() {
        INFINISPAN.start();
        nodeA = client();
        nodeB = client();
        cacheA = awaitUsableCache(nodeA);
        cacheB = awaitUsableCache(nodeB);
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

    /** Creating the cache from the client configuration is asynchronous; a real write proves it is ready. */
    private static RemoteCache<String, String> awaitUsableCache(RemoteCacheManager manager) {
        IllegalLifecycleStateException last = null;
        Instant deadline = Instant.now().plus(Duration.ofMinutes(2));
        while (Instant.now().isBefore(deadline)) {
            try {
                RemoteCache<String, String> cache =
                        manager.getCache(InfinispanPendingAuthorizationStore.CACHE_NAME);
                cache.put("warmup", "1", 5, TimeUnit.SECONDS);
                cache.remove("warmup");
                return cache;
            } catch (IllegalLifecycleStateException e) {
                last = e;
                try {
                    Thread.sleep(500);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted waiting for the cache", interrupted);
                }
            }
        }
        throw new IllegalStateException("cache never became usable", last);
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
        config.remoteCache(InfinispanPendingAuthorizationStore.CACHE_NAME)
                .configuration(
                        "{\"distributed-cache\":{\"encoding\":{\"media-type\":\"application/x-protostream\"}}}");
        return new RemoteCacheManager(config.build());
    }

    private static InfinispanPendingAuthorizationStore storeOn(RemoteCache<String, String> cache, Instant now) {
        return new InfinispanPendingAuthorizationStore(cache, Clock.fixed(now, ZoneOffset.UTC));
    }

    private static RealmKey realm() {
        return new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(UUID.randomUUID()));
    }

    private static PendingAuthorization pending(RealmKey realm, Duration lifetime, String nonce) {
        AuthorizationRequest request = new AuthorizationRequest(
                realm,
                "public-spa",
                "https://rp.example/callback",
                new LinkedHashSet<>(List.of("openid", "profile")),
                "state-" + UUID.randomUUID(),
                nonce,
                CodeChallenge.s256("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        return new PendingAuthorization(
                "txn-" + UUID.randomUUID(), request, "csrf-" + UUID.randomUUID(), "binding-hash",
                T0, T0.plus(lifetime));
    }

    @Test
    @DisplayName("a sign-in parked by one node is read and consumed intact by another, with or without a nonce")
    void parkedOnOneNodeFinishesOnAnother() {
        for (String nonce : new String[] {"nonce-1", null}) {
            RealmKey realm = realm();
            PendingAuthorization parked = pending(realm, Duration.ofMinutes(10), nonce);
            storeOn(cacheA, T0).store(parked).await().atMost(WAIT);

            assertThat(storeOn(cacheB, T0).find(realm, parked.transactionId()).await().atMost(WAIT))
                    .isEqualTo(parked);
            assertThat(storeOn(cacheB, T0).consume(realm, parked.transactionId()).await().atMost(WAIT))
                    .isEqualTo(parked);
            assertThat(storeOn(cacheA, T0).find(realm, parked.transactionId()).await().atMost(WAIT))
                    .isNull();
        }
    }

    @Test
    @DisplayName("concurrent consumes of one sign-in yield exactly one entry")
    void concurrentConsumeYieldsOne() throws Exception {
        RealmKey realm = realm();
        PendingAuthorization parked = pending(realm, Duration.ofMinutes(10), null);
        storeOn(cacheA, T0).store(parked).await().atMost(WAIT);

        int attempts = 8;
        InfinispanPendingAuthorizationStore a = storeOn(cacheA, T0);
        InfinispanPendingAuthorizationStore b = storeOn(cacheB, T0);
        ExecutorService pool = Executors.newFixedThreadPool(attempts);
        try {
            List<Callable<PendingAuthorization>> consumes = new ArrayList<>();
            for (int i = 0; i < attempts; i++) {
                InfinispanPendingAuthorizationStore store = (i % 2 == 0) ? a : b;
                consumes.add(() -> store.consume(realm, parked.transactionId()).await().atMost(WAIT));
            }
            long won = 0;
            for (Future<PendingAuthorization> result : pool.invokeAll(consumes)) {
                if (result.get() != null) {
                    won++;
                }
            }
            assertThat(won).isEqualTo(1);
        } finally {
            pool.shutdownNow();
            assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        }
    }

    @Test
    @DisplayName("a sign-in parked under one realm is a miss under another, and survives the attempt")
    void notVisibleAcrossRealms() {
        RealmKey owner = realm();
        PendingAuthorization parked = pending(owner, Duration.ofMinutes(10), null);
        storeOn(cacheA, T0).store(parked).await().atMost(WAIT);

        assertThat(storeOn(cacheB, T0).find(realm(), parked.transactionId()).await().atMost(WAIT)).isNull();
        assertThat(storeOn(cacheB, T0).consume(realm(), parked.transactionId()).await().atMost(WAIT)).isNull();
        assertThat(storeOn(cacheB, T0).consume(owner, parked.transactionId()).await().atMost(WAIT)).isNotNull();
    }

    @Test
    @DisplayName("a sign-in is a miss once its lifetime has elapsed")
    void expires() {
        RealmKey realm = realm();
        PendingAuthorization parked = pending(realm, Duration.ofSeconds(1), null);
        storeOn(cacheA, T0).store(parked).await().atMost(WAIT);

        assertThat(storeOn(cacheB, T0.plusSeconds(5)).find(realm, parked.transactionId()).await().atMost(WAIT))
                .isNull();
    }

    @Test
    @DisplayName("an already-expired entry is refused rather than stored without a lifespan")
    void refusesExpired() {
        InfinispanPendingAuthorizationStore store = storeOn(cacheA, T0.plusSeconds(3600));

        assertThatThrownBy(() -> store.store(pending(realm(), Duration.ofMinutes(10), null)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
