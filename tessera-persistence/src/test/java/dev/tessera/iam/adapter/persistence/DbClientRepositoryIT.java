package dev.tessera.iam.adapter.persistence;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
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
import org.hibernate.PropertyValueException;
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

    @Inject
    ClientKeySourcePort keySource;

    private static final String PUBLIC_KEY =
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
                    + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
    private static final String JWKS = "{\"keys\":[" + PUBLIC_KEY + "]}";

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
    @DisplayName("a private_key_jwt client's keys are its assertion trust; a secret client has none")
    void keyedClientResolvesItsAssertionTrust(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID keyedId = UUID.randomUUID();
        UUID secretId = UUID.randomUUID();
        OAuthClientEntity keyed = confidential(tenant, keyedId, "keyed-app", null);
        keyed.authMethod = "PRIVATE_KEY_JWT";
        keyed.jwks = JWKS;

        asserter.execute(() -> scoped(tenant, s -> s.persist(keyed).call(s::flush)));
        asserter.execute(() -> scoped(tenant, s ->
                s.persist(confidential(tenant, secretId, "secret-app", "hash")).call(s::flush)));
        asserter.assertThat(() -> keySource.trustFor(realm(tenant), new ClientId(keyedId)), trust -> {
            Assertions.assertThat(trust.issuer()).isEqualTo("keyed-app");
            Assertions.assertThat(trust.subject()).isEqualTo("keyed-app");
            Assertions.assertThat(trust.jwks().replace(" ", "")).contains("\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\"");
        });
        asserter.assertThat(() -> keySource.trustFor(realm(tenant), new ClientId(secretId)),
                trust -> Assertions.assertThat(trust).isNull());
        asserter.assertThat(() -> keySource.trustFor(realm(UUID.randomUUID()), new ClientId(keyedId)),
                trust -> Assertions.assertThat(trust).isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a workload-identity client's trust is its issuer and subject; one with a secret or keys, or an issuer on another client, is refused")
    void workloadIdentityClient(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID workloadId = UUID.randomUUID();
        asserter.execute(() -> scoped(tenant, s -> s.persist(workload(tenant, workloadId, "wl-app", "sa-1")).call(s::flush)));
        asserter.assertThat(() -> keySource.trustFor(realm(tenant), new ClientId(workloadId)), trust ->
                Assertions.assertThat(trust).isEqualTo(
                        ClientKeySourcePort.AssertionTrust.ofIssuer("https://platform.example", "sa-1")));

        OAuthClientEntity withSecret = workload(tenant, UUID.randomUUID(), "wl-secret", "sa-2");
        withSecret.secretHash = "hash";
        OAuthClientEntity noSubject = workload(tenant, UUID.randomUUID(), "wl-nosub", "sa-3");
        noSubject.assertionSubject = null;
        OAuthClientEntity secretWithIssuer = confidential(tenant, UUID.randomUUID(), "secret-issuer", "hash");
        secretWithIssuer.assertionIssuer = "https://platform.example";
        for (OAuthClientEntity refused : List.of(withSecret, noSubject)) {
            asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(refused).call(s::flush)), failure ->
                    Assertions.assertThat(failure).hasStackTraceContaining("ck_oauth_client_workload_identity_shape"));
        }
        asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(secretWithIssuer).call(s::flush)), failure ->
                Assertions.assertThat(failure).hasStackTraceContaining("ck_oauth_client_issuer_only_for_workload_identity"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("one workload identity is one client: a second registration of the pair is refused, in any tenant")
    void workloadIdentityIsUniqueAcrossTenants(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        UUID otherTenant = UUID.randomUUID();
        String subject = "sa-" + UUID.randomUUID();
        asserter.execute(() -> scoped(tenant, s ->
                s.persist(workload(tenant, UUID.randomUUID(), "wl-first", subject)).call(s::flush)));
        for (UUID where : List.of(tenant, otherTenant)) {
            OAuthClientEntity second = workload(where, UUID.randomUUID(), "wl-second", subject);
            asserter.assertFailedWith(() -> scoped(where, s -> s.persist(second).call(s::flush)), failure ->
                    Assertions.assertThat(failure).hasStackTraceContaining("uq_oauth_client_workload_identity"));
        }
    }

    private static OAuthClientEntity workload(UUID tenant, UUID id, String key, String subject) {
        OAuthClientEntity e = confidential(tenant, id, key, null);
        e.authMethod = "WORKLOAD_IDENTITY";
        e.assertionIssuer = "https://platform.example";
        e.assertionSubject = subject;
        return e;
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a private_key_jwt client with a secret, and keys on a secret client, are refused")
    void oneAuthenticationMethodPerClient(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        OAuthClientEntity keyedWithSecret = confidential(tenant, UUID.randomUUID(), "keyed-with-secret", "hash");
        keyedWithSecret.authMethod = "PRIVATE_KEY_JWT";
        keyedWithSecret.jwks = JWKS;
        OAuthClientEntity secretWithKeys = confidential(tenant, UUID.randomUUID(), "secret-with-keys", "hash");
        secretWithKeys.jwks = JWKS;

        asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(keyedWithSecret).call(s::flush)),
                failure -> Assertions.assertThat(failure).hasStackTraceContaining("ck_oauth_client_key_auth_has_no_secret"));
        asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(secretWithKeys).call(s::flush)),
                failure -> Assertions.assertThat(failure).hasStackTraceContaining("ck_oauth_client_jwks_only_for_key_auth"));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a JWKS with private material, too many keys, no keys, a repeated keys member or over 16 KiB is refused")
    void onlyABoundedPublicKeySetIsRegistrable(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        String privateKey = PUBLIC_KEY.replace("}", ",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\"}");
        List<String> refused = List.of(
                "{\"keys\":[" + privateKey + "]}",
                "{\"keys\":[" + String.join(",", java.util.Collections.nCopies(11, PUBLIC_KEY)) + "]}",
                "{\"keys\":[]}",
                "{\"keys\":[" + PUBLIC_KEY + "],\"keys\":[" + privateKey + "]}",
                "{\"keys\":[" + PUBLIC_KEY + "],\"padding\":\"" + "x".repeat(16384) + "\"}");
        for (String jwks : refused) {
            OAuthClientEntity keyed = confidential(tenant, UUID.randomUUID(), "keyed-" + refused.indexOf(jwks), null);
            keyed.authMethod = "PRIVATE_KEY_JWT";
            keyed.jwks = jwks;
            asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(keyed).call(s::flush)),
                    failure -> Assertions.assertThat(failure)
                            .hasStackTraceContaining("ck_oauth_client_jwks_public_and_bounded"));
        }

        // A bare array is not a JWK Set; the jsonb mapping refuses it before the database does.
        OAuthClientEntity array = confidential(tenant, UUID.randomUUID(), "keyed-array", null);
        array.authMethod = "PRIVATE_KEY_JWT";
        array.jwks = "[" + PUBLIC_KEY + "]";
        asserter.assertFailedWith(() -> scoped(tenant, s -> s.persist(array).call(s::flush)),
                failure -> Assertions.assertThat(failure).isNotNull());

        // A repeated keys member collapses to its last copy before the check, and only that is stored.
        UUID collapsedId = UUID.randomUUID();
        OAuthClientEntity collapsed = confidential(tenant, collapsedId, "keyed-collapsed", null);
        collapsed.authMethod = "PRIVATE_KEY_JWT";
        collapsed.jwks = "{\"keys\":[" + privateKey + "],\"keys\":[" + PUBLIC_KEY + "]}";
        asserter.execute(() -> scoped(tenant, s -> s.persist(collapsed).call(s::flush)));
        asserter.assertThat(() -> keySource.trustFor(realm(tenant), new ClientId(collapsedId)),
                trust -> Assertions.assertThat(trust.jwks()).doesNotContain("\"d\""));
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

    @Test
    @RunOnVertxContext
    @DisplayName("a client with no tenant binding cannot be registered, through the entity or in SQL")
    void clientWithoutTenantIsRefused(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        OAuthClientEntity unbound = confidential(null, UUID.randomUUID(), "unbound-service", null);
        unbound.allowedGrants = "client_credentials";
        unbound.audiences = "https://orders.example";

        // The entity: Hibernate refuses the null tenant before any SQL is sent.
        asserter.assertFailedWith(
                () -> scoped(tenant, s -> s.persist(unbound).call(s::flush)),
                failure -> Assertions.assertThat(causes(failure)).anySatisfy(t -> Assertions.assertThat(t)
                        .isInstanceOfSatisfying(PropertyValueException.class,
                                e -> Assertions.assertThat(e.getPropertyName()).isEqualTo("tenantId"))));
        // A row written directly: the oauth_client row-level security policy refuses it (42501),
        // since a null tenant_id never equals the bound tenant.
        asserter.assertFailedWith(
                () -> scoped(tenant, s -> s.createNativeQuery(
                                "insert into oauth_client (id, tenant_id, baseline_id, client_key, client_type,"
                                        + " allowed_grants, audiences, created_at)"
                                        + " values (:id, null, :baseline, 'unbound-sql', 'CONFIDENTIAL',"
                                        + " 'client_credentials', 'https://orders.example', now())")
                        .setParameter("id", UUID.randomUUID())
                        .setParameter("baseline", new UUID(0L, 0L))
                        .executeUpdate()),
                failure -> Assertions.assertThat(causes(failure)).anySatisfy(t -> Assertions.assertThat(t.getMessage())
                        .contains("violates row-level security policy")
                        .contains("42501")));
        // And the column itself is NOT NULL, which the policy keeps the application role from reaching.
        asserter.assertEquals(
                () -> scoped(tenant, s -> s.createNativeQuery(
                                "select is_nullable from information_schema.columns"
                                        + " where table_name = 'oauth_client' and column_name = 'tenant_id'",
                                String.class)
                        .getSingleResult()),
                "NO");
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "unbound-service"),
                found -> Assertions.assertThat(found).isNull());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("the ids reserved for unknown-client sentinels cannot be registered")
    void sentinelIdsAreReserved(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        for (UUID reserved : List.of(new UUID(0L, 0L), ClientSecretVerifierPort.unknownClient("web-app").value())) {
            asserter.assertFailedWith(
                    () -> scoped(tenant, s -> s.persist(confidential(tenant, reserved, "sentinel-" + reserved, null))
                            .call(s::flush)),
                    failure -> Assertions.assertThat(causes(failure)).anySatisfy(t -> Assertions.assertThat(t)
                            .isInstanceOf(IllegalArgumentException.class)
                            .hasMessageContaining("is reserved")));
        }
        // Positive control: a random (version 4) id registers.
        asserter.execute(() -> scoped(tenant, s -> s.persist(confidential(tenant, UUID.randomUUID(), "random-id", null))
                .call(s::flush)));
        asserter.assertThat(
                () -> clientRepository.findByClientId(realm(tenant), "random-id"),
                found -> Assertions.assertThat(found).isNotNull());
    }

    private static List<Throwable> causes(Throwable failure) {
        List<Throwable> chain = new ArrayList<>();
        for (Throwable t = failure; t != null && !chain.contains(t); t = t.getCause()) {
            chain.add(t);
        }
        return chain;
    }

    /** Hibernate may wrap a lifecycle-callback exception; the refusal must be in the chain. */
    private static void assertInvalidRedirectUri(Throwable failure) {
        Assertions.assertThat(causes(failure))
                .anySatisfy(t -> Assertions.assertThat(t)
                        .isInstanceOfSatisfying(InvalidRedirectUriException.class,
                                e -> Assertions.assertThat(e.error()).isEqualTo("invalid_redirect_uri")));
    }
}
