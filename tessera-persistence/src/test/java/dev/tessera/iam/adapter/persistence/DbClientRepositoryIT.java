package dev.tessera.iam.adapter.persistence;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.InvalidRedirectUriException;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import org.assertj.core.api.Assertions;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the DB-backed confidential-client spine end-to-end against real PostgreSQL:
 * the {@link ClientRepositoryPort} resolves a registered client from its wire {@code client_id}
 * and the {@link ClientSecretVerifierPort} accepts the correct Argon2id secret and rejects a
 * wrong one — all tenant-scoped through row-level security, so one tenant can neither resolve
 * nor authenticate another tenant's client. Requires Docker (Testcontainers); runs in CI.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("DB client registry + Argon2id secret verifier (PostgreSQL integration)")
class DbClientRepositoryIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");
    // Small Argon2 parameters keep the fixture fast; the verifier reads parameters from the
    // stored PHC, so this only affects how quickly the seed hash is produced.
    private static final Argon2Function FAST = Argon2Function.getInstance(1024, 1, 1, 32, Argon2.ID);

    @Inject
    Mutiny.SessionFactory sessionFactory;

    @Inject
    ClientRepositoryPort clientRepository;

    @Inject
    ClientSecretVerifierPort secretVerifier;

    private static Uni<String> setScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }

    private <T> Uni<T> scoped(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return sessionFactory.withTransaction(
                (session, tx) -> setScope(session, tenantId).chain(() -> work.apply(session)));
    }

    private static OAuthClientEntity confidential(UUID tenantId, UUID id, String key, String secretHash) {
        OAuthClientEntity e = new OAuthClientEntity();
        e.id = id;
        e.tenantId = tenantId;
        e.baselineId = new UUID(0L, 0L);
        e.clientKey = key;
        e.clientType = ClientType.CONFIDENTIAL;
        e.authMethod = "CLIENT_SECRET";
        e.allowedGrants = "authorization_code";
        e.redirectUris = "https://client.example/callback";
        e.secretHash = secretHash;
        e.createdAt = T0;
        return e;
    }

    private static OAuthClientEntity publicClient(UUID tenantId, String key, String redirectUris) {
        OAuthClientEntity e = new OAuthClientEntity();
        e.id = UUID.randomUUID();
        e.tenantId = tenantId;
        e.baselineId = new UUID(0L, 0L);
        e.clientKey = key;
        e.clientType = ClientType.PUBLIC;
        e.allowedGrants = "authorization_code";
        e.redirectUris = redirectUris;
        e.createdAt = T0;
        return e;
    }

    private static RealmKey realm(UUID tenantId) {
        return new RealmKey(new TenantId(tenantId), new BaselineId(new UUID(0L, 0L)));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a registered client resolves by client_id; its correct secret verifies, a wrong one does not")
    void resolvesClientAndVerifiesSecret(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        String hash = Password.hash("correct-secret").with(FAST).getResult();

        asserter.execute(() -> scoped(tenant, s ->
                s.persist(confidential(tenant, clientId, "web-app", hash)).call(s::flush)));

        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "web-app"),
                client -> {
                    org.assertj.core.api.Assertions.assertThat(client)
                            .isInstanceOf(ConfidentialClient.class);
                    org.assertj.core.api.Assertions.assertThat(client.id().value()).isEqualTo(clientId);
                    org.assertj.core.api.Assertions.assertThat(client.redirectUris())
                            .containsExactly("https://client.example/callback");
                });

        asserter.assertEquals(
                () -> secretVerifier.verifySecret(realm(tenant), new ClientId(clientId), "correct-secret"),
                Boolean.TRUE);
        asserter.assertEquals(
                () -> secretVerifier.verifySecret(realm(tenant), new ClientId(clientId), "WRONG"),
                Boolean.FALSE);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unknown client_id resolves to null")
    void unknownClientResolvesNull(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "no-such-client"),
                client -> org.assertj.core.api.Assertions.assertThat(client).isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("RLS isolates the registry: tenant B can neither resolve nor authenticate tenant A's client")
    void tenantIsolation(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        String hash = Password.hash("a-secret").with(FAST).getResult();

        asserter.execute(() -> scoped(tenantA, s ->
                s.persist(confidential(tenantA, clientId, "shared-key", hash)).call(s::flush)));

        // Under tenant B, tenant A's client is invisible (RLS) → null resolution.
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenantB), "shared-key"),
                client -> org.assertj.core.api.Assertions.assertThat(client).isNull());
        // And its secret cannot be verified under B — no row visible, fail closed.
        asserter.assertEquals(
                () -> secretVerifier.verifySecret(realm(tenantB), new ClientId(clientId), "a-secret"),
                Boolean.FALSE);
        // Sanity: under tenant A it still authenticates.
        asserter.assertEquals(
                () -> secretVerifier.verifySecret(realm(tenantA), new ClientId(clientId), "a-secret"),
                Boolean.TRUE);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("registering a client with a plain-http redirect URI is refused with invalid_redirect_uri")
    void httpRedirectUriIsRefusedAtRegistration(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        OAuthClientEntity client = confidential(tenant, UUID.randomUUID(), "http-app", null);
        client.redirectUris = "https://client.example/callback http://client.example/callback";

        asserter.assertFailedWith(
                () -> scoped(tenant, s -> s.persist(client).call(s::flush)),
                DbClientRepositoryIT::assertInvalidRedirectUri);
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "http-app"),
                found -> Assertions.assertThat(found).isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("updating a registered client to a plain-http redirect URI is refused with invalid_redirect_uri")
    void httpRedirectUriIsRefusedAtUpdate(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();

        asserter.execute(() -> scoped(tenant, s ->
                s.persist(confidential(tenant, clientId, "updated-app", null)).call(s::flush)));
        asserter.assertFailedWith(
                () -> scoped(tenant, s -> s.find(OAuthClientEntity.class, clientId)
                        .invoke(found -> found.redirectUris = "http://client.example/callback")
                        .call(s::flush)),
                DbClientRepositoryIT::assertInvalidRedirectUri);
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "updated-app"),
                found -> Assertions.assertThat(found.redirectUris())
                        .containsExactly("https://client.example/callback"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a public client registers loopback http and a private-use scheme, but not plain http to a remote host")
    void publicClientRedirectUris(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        OAuthClientEntity nativeApp = publicClient(tenant, "native-app",
                "http://127.0.0.1:8400/cb com.example.app:/oauth2redirect");
        OAuthClientEntity remoteHttp = publicClient(tenant, "remote-http", "http://client.example/callback");

        asserter.execute(() -> scoped(tenant, s -> s.persist(nativeApp).call(s::flush)));
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "native-app"),
                found -> {
                    Assertions.assertThat(found).isInstanceOf(PublicClient.class);
                    Assertions.assertThat(found.redirectUris())
                            .containsExactly("http://127.0.0.1:8400/cb", "com.example.app:/oauth2redirect");
                });
        asserter.assertFailedWith(
                () -> scoped(tenant, s -> s.persist(remoteHttp).call(s::flush)),
                DbClientRepositoryIT::assertInvalidRedirectUri);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a client_credentials registration resolves its scopes, audiences and roles in its own tenant only")
    void clientCredentialsRegistrationIsTenantBound(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        OAuthClientEntity service = confidential(tenantA, UUID.randomUUID(), "orders-service", null);
        service.allowedGrants = "client_credentials";
        service.redirectUris = null;
        service.allowedScopes = "orders.read orders.write";
        service.audiences = "https://orders.example https://billing.example";
        service.roles = "ops reader";

        asserter.execute(() -> scoped(tenantA, s -> s.persist(service).call(s::flush)));
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenantA), "orders-service"),
                found -> Assertions.assertThat(found).isInstanceOfSatisfying(ConfidentialClient.class, c -> {
                    Assertions.assertThat(c.allowedScopes()).containsExactly("orders.read", "orders.write");
                    Assertions.assertThat(c.audiences())
                            .containsExactly("https://orders.example", "https://billing.example");
                    Assertions.assertThat(c.roles()).containsExactly("ops", "reader");
                }));
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenantB), "orders-service"),
                found -> Assertions.assertThat(found).isNull());
    }

    /** Hibernate may wrap a lifecycle-callback exception; the refusal must be in the chain. */
    private static void assertInvalidRedirectUri(Throwable failure) {
        List<Throwable> chain = new ArrayList<>();
        for (Throwable t = failure; t != null && !chain.contains(t); t = t.getCause()) {
            chain.add(t);
        }
        Assertions.assertThat(chain)
                .anySatisfy(t -> Assertions.assertThat(t)
                        .isInstanceOfSatisfying(InvalidRedirectUriException.class,
                                e -> Assertions.assertThat(e.error()).isEqualTo("invalid_redirect_uri")));
    }
}
