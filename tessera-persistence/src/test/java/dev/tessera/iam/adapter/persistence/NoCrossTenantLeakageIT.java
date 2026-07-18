package dev.tessera.iam.adapter.persistence;

import dev.tessera.iam.adapter.persistence.entity.AuthSessionEntity;
import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.ConsentEntity;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.adapter.persistence.entity.SigningKeyEntity;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import dev.tessera.iam.domain.tenancy.TimeOrderedUuid;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.tuples.Tuple2;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import org.assertj.core.api.Assertions;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves PostgreSQL row-level security keeps two tenants isolated when their work runs
 * <em>concurrently</em> — the leakage risk the per-table sequential isolation ITs
 * ({@code CoreEntitiesRlsIsolationIT}, {@code IamRlsIsolationIT}) do not exercise.
 *
 * <p>The tenant scope is bound with {@code set_config('app.tenant_id', ..., true)} — a
 * transaction-local GUC. Correctness therefore hinges on each concurrent transaction
 * carrying its own binding on its own pooled connection; a binding that bled across
 * connections would let one tenant read or write another's rows. This test drives the
 * two tenants through the production chokepoint bean, {@link TenantScopedSession}, as two
 * concurrent tenant sessions on the reactive event loop (distinct pooled connections
 * model the multi-node case: independent nodes sharing one database, each binding its
 * own tenant), and asserts across the five core tables — {@code iam_user},
 * {@code oauth_client}, {@code auth_session}, {@code signing_key}, {@code consent} — that
 * neither tenant ever observes the other's rows, and that a cross-tenant write is
 * rejected even when interleaved with the owner's legitimate write.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("IAM RLS — no cross-tenant leakage under concurrent two-tenant load (PostgreSQL integration)")
class NoCrossTenantLeakageIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    // Enough concurrent rounds to shake out a GUC bleed that a single lucky scheduling
    // could hide; each round uses a fresh tenant pair against the shared DB.
    private static final int ROUNDS = 8;

    @Inject
    TenantScopedSession tenantScope;

    // -------------------------------------------------------------------------
    // Per-tenant markers — every seeded row carries the tenant's label so a leaked
    // row would be detected by identity, not only by count.
    // -------------------------------------------------------------------------

    private record Marker(UUID tenantId, String label) {
        String subject() {
            return "sub-" + label;
        }

        String clientKey() {
            return "client-" + label;
        }

        String sessionState() {
            return "STARTED-" + label;
        }

        String kid() {
            return "kid-" + label;
        }

        String scopes() {
            return "scope-" + label;
        }
    }

    /** What a tenant sees across the five core tables from inside its own scoped session. */
    private record TenantView(
            long users, long clients, long sessions, long keys, long consents, String userSubject, String clientKey) {}

    // -------------------------------------------------------------------------
    // Entity factories — mirror the sequential isolation ITs.
    // -------------------------------------------------------------------------

    private static UserEntity user(Marker m) {
        UserEntity e = new UserEntity();
        e.id = UUID.randomUUID();
        e.tenantId = m.tenantId();
        e.baselineId = UUID.randomUUID();
        e.subjectId = m.subject();
        e.username = m.subject() + "-login";
        e.createdAt = T0;
        return e;
    }

    private static OAuthClientEntity client(Marker m) {
        OAuthClientEntity e = new OAuthClientEntity();
        e.id = UUID.randomUUID();
        e.tenantId = m.tenantId();
        e.baselineId = UUID.randomUUID();
        e.clientKey = m.clientKey();
        e.clientType = ClientType.CONFIDENTIAL;
        e.authMethod = "CLIENT_SECRET";
        e.allowedGrants = "authorization_code";
        e.createdAt = T0;
        return e;
    }

    private static AuthSessionEntity session(Marker m) {
        AuthSessionEntity e = new AuthSessionEntity();
        e.id = TimeOrderedUuid.generate();
        e.tenantId = m.tenantId();
        e.baselineId = UUID.randomUUID();
        e.state = m.sessionState();
        e.createdAt = T0;
        return e;
    }

    private static SigningKeyEntity key(Marker m) {
        SigningKeyEntity e = new SigningKeyEntity();
        e.id = UUID.randomUUID();
        e.tenantId = m.tenantId();
        e.kid = m.kid();
        e.algorithm = "EdDSA";
        e.state = SigningKeyState.ACTIVE;
        e.publicJwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + m.kid() + "\"}";
        e.createdAt = T0;
        return e;
    }

    private static ConsentEntity consent(Marker m) {
        ConsentEntity e = new ConsentEntity();
        e.id = UUID.randomUUID();
        e.tenantId = m.tenantId();
        e.baselineId = UUID.randomUUID();
        e.userId = UUID.randomUUID();
        e.clientId = UUID.randomUUID();
        e.grantedScopes = m.scopes();
        e.grantedAt = T0;
        e.createdAt = T0;
        return e;
    }

    // -------------------------------------------------------------------------
    // Scoped units of work — run through the production chokepoint bean.
    // -------------------------------------------------------------------------

    /** Persists one row into each of the five core tables in a single tenant-scoped transaction. */
    private Uni<Void> seed(Marker m) {
        return tenantScope.inTenant(m.tenantId(), s -> s.persist(user(m))
                .chain(() -> s.persist(client(m)))
                .chain(() -> s.persist(session(m)))
                .chain(() -> s.persist(key(m)))
                .chain(() -> s.persist(consent(m)))
                .call(s::flush));
    }

    /** Reads every core table from inside one tenant-scoped session and captures what it sees. */
    private Uni<TenantView> readAll(UUID tenantId) {
        return tenantScope.inTenant(tenantId, s -> count(s, "UserEntity", "u")
                .flatMap(users -> count(s, "OAuthClientEntity", "c")
                        .flatMap(clients -> count(s, "AuthSessionEntity", "a")
                                .flatMap(sessions -> count(s, "SigningKeyEntity", "k")
                                        .flatMap(keys -> count(s, "ConsentEntity", "n")
                                                .flatMap(consents -> firstUserSubject(s)
                                                        .flatMap(subject -> firstClientKey(s)
                                                                .map(clientKey -> new TenantView(
                                                                        users, clients, sessions, keys, consents,
                                                                        subject, clientKey)))))))));
    }

    private static Uni<Long> count(Mutiny.Session s, String entity, String alias) {
        return s.createQuery("select count(" + alias + ") from " + entity + " " + alias, Long.class)
                .getSingleResult();
    }

    private static Uni<String> firstUserSubject(Mutiny.Session s) {
        return s.createQuery("from UserEntity", UserEntity.class)
                .getResultList()
                .map(rows -> rows.isEmpty() ? null : rows.get(0).subjectId);
    }

    private static Uni<String> firstClientKey(Mutiny.Session s) {
        return s.createQuery("from OAuthClientEntity", OAuthClientEntity.class)
                .getResultList()
                .map(rows -> rows.isEmpty() ? null : rows.get(0).clientKey);
    }

    private static void assertSeesOnlyItself(TenantView view, Marker owner) {
        Assertions.assertThat(view.users()).as("users visible to %s", owner.label()).isEqualTo(1L);
        Assertions.assertThat(view.clients()).as("clients visible to %s", owner.label()).isEqualTo(1L);
        Assertions.assertThat(view.sessions()).as("sessions visible to %s", owner.label()).isEqualTo(1L);
        Assertions.assertThat(view.keys()).as("keys visible to %s", owner.label()).isEqualTo(1L);
        Assertions.assertThat(view.consents()).as("consents visible to %s", owner.label()).isEqualTo(1L);
        Assertions.assertThat(view.userSubject()).as("user identity visible to %s", owner.label())
                .isEqualTo(owner.subject());
        Assertions.assertThat(view.clientKey()).as("client identity visible to %s", owner.label())
                .isEqualTo(owner.clientKey());
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("two tenants seeding and reading all core tables concurrently never observe each other's rows")
    void concurrentTenantsNeverLeak(UniAsserter asserter) {
        for (int round = 0; round < ROUNDS; round++) {
            Marker a = new Marker(UUID.randomUUID(), "a");
            Marker b = new Marker(UUID.randomUUID(), "b");

            // Two concurrent tenant sessions write their rows at the same time.
            asserter.execute(() -> Uni.combine().all().unis(seed(a), seed(b)).discardItems());

            // Two concurrent tenant sessions read every table at the same time; each must
            // see exactly its own single row per table and never the other tenant's.
            asserter.assertThat(
                    () -> Uni.combine().all().unis(readAll(a.tenantId()), readAll(b.tenantId())).asTuple(),
                    views -> {
                        assertSeesOnlyItself(views.getItem1(), a);
                        assertSeesOnlyItself(views.getItem2(), b);
                    });
        }
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a cross-tenant write is rejected even when interleaved with the owner's concurrent legitimate write")
    void concurrentCrossTenantWriteRejected(UniAsserter asserter) {
        Marker a = new Marker(UUID.randomUUID(), "a");
        UUID intruder = UUID.randomUUID();

        // Legitimate: tenant A writes its own user. Illegal: a session scoped to the
        // intruder tries to write a row stamped with tenant A's id — a WITH CHECK
        // violation that must fail even while A's own write proceeds concurrently.
        Uni<Void> legitimate = tenantScope.inTenant(a.tenantId(), s -> s.persist(user(a)).call(s::flush));
        Uni<Void> crossTenant = tenantScope.inTenant(
                intruder, s -> s.persist(user(new Marker(a.tenantId(), "intruder"))).call(s::flush));

        // collectFailures lets both branches run to completion before the combined Uni
        // reports the intruder's failure, so tenant A's own transaction has committed by
        // the time this assertion fires.
        asserter.assertFailedWith(
                () -> Uni.combine().all().unis(legitimate, crossTenant).collectFailures().discardItems(),
                Throwable.class);

        // Only the intruder's write must have failed: tenant A sees exactly its own one
        // user and nothing the intruder tried to stamp with A's id. A count of 1 rules out
        // an intruder row wrongly slipping in; the subject confirms it is A's own row. This
        // also guards against the whole assertion passing when both writes wrongly failed.
        asserter.assertThat(
                () -> tenantScope.inTenant(a.tenantId(),
                        s -> s.createQuery("from UserEntity", UserEntity.class).getResultList()),
                rows -> {
                    Assertions.assertThat(rows)
                            .as("tenant A's own concurrent write committed while the intruder's was rejected")
                            .hasSize(1);
                    Assertions.assertThat(rows.get(0).subjectId).isEqualTo(a.subject());
                });
    }
}
