package dev.tessera.iam.adapter.persistence;

import dev.tessera.iam.adapter.persistence.entity.AuthSessionEntity;
import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.ConsentEntity;
import dev.tessera.iam.adapter.persistence.entity.CredentialEntity;
import dev.tessera.iam.adapter.persistence.entity.CredentialKind;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.adapter.persistence.entity.RefreshTokenFamilyEntity;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.domain.tenancy.TimeOrderedUuid;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves PostgreSQL row-level security isolates tenants over the core domain tables —
 * {@code iam_user}, {@code iam_credential}, {@code oauth_client}, {@code consent},
 * {@code auth_session} (time-ordered UUIDv7 primary key) and {@code refresh_token_family}
 * (also UUIDv7) — end-to-end.
 *
 * <p>The reactive datasource connects as a least-privilege non-superuser role so RLS is
 * enforced. Each transaction sets {@code app.tenant_id} exactly as the persistence
 * chokepoint does, then reads or writes a table. Uses fresh tenant ids per method (the
 * container/DB is shared) and asserts, for each table: a tenant sees only its own rows;
 * writing another tenant's row is rejected by {@code WITH CHECK}; and an unscoped
 * transaction sees nothing — the schema fails closed.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("IAM RLS — no cross-tenant leakage over the core entity tables (PostgreSQL integration)")
class CoreEntitiesRlsIsolationIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    @Inject
    Mutiny.SessionFactory sessionFactory;

    // -------------------------------------------------------------------------
    // Helpers — set the tenant GUC exactly like the persistence chokepoint.
    // -------------------------------------------------------------------------

    private static Uni<String> setScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }

    /** Runs work in a transaction scoped to {@code tenantId}. */
    private <T> Uni<T> scoped(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return sessionFactory.withTransaction(
                (session, tx) -> setScope(session, tenantId).chain(() -> work.apply(session)));
    }

    /** Runs work in a transaction with NO tenant bound (fail-closed path). */
    private <T> Uni<T> unscoped(Function<Mutiny.Session, Uni<T>> work) {
        return sessionFactory.withTransaction((session, tx) -> work.apply(session));
    }

    // -------------------------------------------------------------------------
    // Entity factories — random v4 ids for low-volume tables, UUIDv7 for the
    // append-heavy ones (auth_session, refresh_token_family).
    // -------------------------------------------------------------------------

    private static UserEntity user(UUID tenantId, String subject) {
        UserEntity entity = new UserEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.subjectId = subject;
        entity.username = subject + "-login";
        entity.createdAt = T0;
        return entity;
    }

    private static AuthSessionEntity session(UUID tenantId, String state) {
        AuthSessionEntity entity = new AuthSessionEntity();
        entity.id = TimeOrderedUuid.generate();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.state = state;
        entity.createdAt = T0;
        return entity;
    }

    private static RefreshTokenFamilyEntity family(UUID tenantId, String tokenHash) {
        RefreshTokenFamilyEntity entity = new RefreshTokenFamilyEntity();
        entity.id = TimeOrderedUuid.generate();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.userId = UUID.randomUUID();
        entity.clientId = UUID.randomUUID();
        entity.currentTokenHash = tokenHash;
        entity.generation = 0;
        entity.reused = false;
        entity.createdAt = T0;
        return entity;
    }

    private static CredentialEntity credential(UUID tenantId, String label) {
        CredentialEntity entity = new CredentialEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.userId = UUID.randomUUID();
        entity.kind = CredentialKind.PASSWORD_HASH;
        entity.material = label.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        entity.label = label;
        entity.createdAt = T0;
        return entity;
    }

    private static OAuthClientEntity client(UUID tenantId, String clientKey) {
        OAuthClientEntity entity = new OAuthClientEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.clientKey = clientKey;
        entity.clientType = ClientType.CONFIDENTIAL;
        entity.authMethod = "CLIENT_SECRET";
        entity.allowedGrants = "authorization_code";
        entity.createdAt = T0;
        return entity;
    }

    private static ConsentEntity consent(UUID tenantId, String scopes) {
        ConsentEntity entity = new ConsentEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.baselineId = UUID.randomUUID();
        entity.userId = UUID.randomUUID();
        entity.clientId = UUID.randomUUID();
        entity.grantedScopes = scopes;
        entity.grantedAt = T0;
        entity.createdAt = T0;
        return entity;
    }

    private Uni<Long> countUsers(Mutiny.Session session) {
        return session.createQuery("select count(u) from UserEntity u", Long.class)
                .getSingleResult();
    }

    private Uni<Long> countCredentials(Mutiny.Session session) {
        return session.createQuery("select count(c) from CredentialEntity c", Long.class)
                .getSingleResult();
    }

    private Uni<Long> countClients(Mutiny.Session session) {
        return session.createQuery("select count(c) from OAuthClientEntity c", Long.class)
                .getSingleResult();
    }

    private Uni<Long> countConsents(Mutiny.Session session) {
        return session.createQuery("select count(c) from ConsentEntity c", Long.class)
                .getSingleResult();
    }

    private Uni<Long> countSessions(Mutiny.Session session) {
        return session.createQuery("select count(s) from AuthSessionEntity s", Long.class)
                .getSingleResult();
    }

    private Uni<Long> countFamilies(Mutiny.Session session) {
        return session.createQuery("select count(f) from RefreshTokenFamilyEntity f", Long.class)
                .getSingleResult();
    }

    // -------------------------------------------------------------------------
    // iam_user (random v4 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own users; neither can read the other's")
    void usersAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(user(tenantA, "sub-a")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(user(tenantB, "sub-b")).call(s::flush)));

        // A sees exactly its own user; B sees exactly its own.
        asserter.assertEquals(() -> scoped(tenantA, this::countUsers), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countUsers), 1L);

        // A's view contains only tenant-A rows.
        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from UserEntity", UserEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).subjectId).isEqualTo("sub-a");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a user owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsUser(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        // Scoped to B, but the row's tenant_id is A → WITH CHECK policy violation.
        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(user(tenantA, "intruder")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no users — fails closed")
    void unscopedSeesNoUsers(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(user(tenantA, "seed")).call(s::flush)));
        // No app.tenant_id set → current_setting is NULL → RLS yields zero rows.
        asserter.assertEquals(() -> unscoped(this::countUsers), 0L);
    }

    // -------------------------------------------------------------------------
    // auth_session (time-ordered UUIDv7 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own auth sessions; neither can read the other's")
    void sessionsAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(session(tenantA, "STARTED")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(session(tenantB, "STARTED")).call(s::flush)));

        asserter.assertEquals(() -> scoped(tenantA, this::countSessions), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countSessions), 1L);

        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from AuthSessionEntity", AuthSessionEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert an auth session owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsSession(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(session(tenantA, "STARTED")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no auth sessions — fails closed")
    void unscopedSeesNoSessions(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(session(tenantA, "STARTED")).call(s::flush)));
        asserter.assertEquals(() -> unscoped(this::countSessions), 0L);
    }

    // -------------------------------------------------------------------------
    // refresh_token_family (time-ordered UUIDv7 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own refresh-token families; neither can read the other's")
    void familiesAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(family(tenantA, "hash-a")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(family(tenantB, "hash-b")).call(s::flush)));

        asserter.assertEquals(() -> scoped(tenantA, this::countFamilies), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countFamilies), 1L);

        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from RefreshTokenFamilyEntity", RefreshTokenFamilyEntity.class)
                                .getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).currentTokenHash).isEqualTo("hash-a");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a refresh-token family owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsFamily(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(family(tenantA, "intruder-hash")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no refresh-token families — fails closed")
    void unscopedSeesNoFamilies(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(family(tenantA, "seed-hash")).call(s::flush)));
        asserter.assertEquals(() -> unscoped(this::countFamilies), 0L);
    }

    // -------------------------------------------------------------------------
    // iam_credential (random v4 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own credentials; neither can read the other's")
    void credentialsAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(credential(tenantA, "cred-a")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(credential(tenantB, "cred-b")).call(s::flush)));

        asserter.assertEquals(() -> scoped(tenantA, this::countCredentials), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countCredentials), 1L);

        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from CredentialEntity", CredentialEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).label).isEqualTo("cred-a");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a credential owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsCredential(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(credential(tenantA, "intruder")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no credentials — fails closed")
    void unscopedSeesNoCredentials(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(credential(tenantA, "seed")).call(s::flush)));
        asserter.assertEquals(() -> unscoped(this::countCredentials), 0L);
    }

    // -------------------------------------------------------------------------
    // oauth_client (random v4 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own clients; neither can read the other's")
    void clientsAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(client(tenantA, "client-a")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(client(tenantB, "client-b")).call(s::flush)));

        asserter.assertEquals(() -> scoped(tenantA, this::countClients), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countClients), 1L);

        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from OAuthClientEntity", OAuthClientEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).clientKey).isEqualTo("client-a");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a client owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsClient(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(client(tenantA, "intruder")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no clients — fails closed")
    void unscopedSeesNoClients(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(client(tenantA, "seed")).call(s::flush)));
        asserter.assertEquals(() -> unscoped(this::countClients), 0L);
    }

    // -------------------------------------------------------------------------
    // consent (random v4 PK)
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own consents; neither can read the other's")
    void consentsAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(consent(tenantA, "openid")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(consent(tenantB, "profile")).call(s::flush)));

        asserter.assertEquals(() -> scoped(tenantA, this::countConsents), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countConsents), 1L);

        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from ConsentEntity", ConsentEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).grantedScopes).isEqualTo("openid");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a consent owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsConsent(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(consent(tenantA, "intruder")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no consents — fails closed")
    void unscopedSeesNoConsents(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(consent(tenantA, "seed")).call(s::flush)));
        asserter.assertEquals(() -> unscoped(this::countConsents), 0L);
    }
}
