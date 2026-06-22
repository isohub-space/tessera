package dev.tessera.iam.adapter.persistence;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.persistence.entity.SigningKeyEntity;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Function;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves PostgreSQL row-level security isolates tenants over the {@code signing_key}
 * table end-to-end.
 *
 * <p>The reactive
 * datasource connects as a least-privilege non-superuser role so RLS is enforced.
 * Each transaction sets {@code app.tenant_id} exactly as the persistence chokepoint
 * does, then reads or writes {@code signing_key}. Uses fresh tenant ids per method
 * (the container/DB is shared) and asserts: a tenant sees only its own keys; writing
 * another tenant's key is rejected by {@code WITH CHECK}; and an unscoped transaction
 * sees nothing — the schema fails closed.</p>
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("IAM RLS — no cross-tenant leakage over signing_key (PostgreSQL integration)")
class IamRlsIsolationIT {

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

    private static SigningKeyEntity key(UUID tenantId, String kid) {
        SigningKeyEntity entity = new SigningKeyEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.kid = kid;
        entity.algorithm = "EdDSA";
        entity.state = SigningKeyState.ACTIVE;
        entity.publicJwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + kid + "\"}";
        entity.createdAt = T0;
        return entity;
    }

    private Uni<Long> countKeys(Mutiny.Session session) {
        return session.createQuery("select count(k) from SigningKeyEntity k", Long.class)
                .getSingleResult();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("each tenant sees only its own signing keys; neither can read the other's")
    void tenantsAreIsolatedForReads(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(key(tenantA, "a-kid")).call(s::flush)));
        asserter.execute(() -> scoped(tenantB, s -> s.persist(key(tenantB, "b-kid")).call(s::flush)));

        // A sees exactly its own key; B sees exactly its own.
        asserter.assertEquals(() -> scoped(tenantA, this::countKeys), 1L);
        asserter.assertEquals(() -> scoped(tenantB, this::countKeys), 1L);

        // A's view contains only tenant-A rows.
        asserter.assertThat(
                () -> scoped(tenantA, s ->
                        s.createQuery("from SigningKeyEntity", SigningKeyEntity.class).getResultList()),
                rows -> {
                    org.assertj.core.api.Assertions.assertThat(rows).hasSize(1);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).tenantId).isEqualTo(tenantA);
                    org.assertj.core.api.Assertions.assertThat(rows.get(0).kid).isEqualTo("a-kid");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a tenant cannot insert a signing key owned by another tenant (WITH CHECK)")
    void cannotWriteAnotherTenantsRow(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();

        // Scoped to B, but the row's tenant_id is A → WITH CHECK policy violation.
        asserter.assertFailedWith(
                () -> scoped(tenantB, s -> s.persist(key(tenantA, "intruder-kid")).call(s::flush)),
                Throwable.class);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an unscoped transaction sees no signing keys — fails closed")
    void unscopedSeesNothing(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();

        asserter.execute(() -> scoped(tenantA, s -> s.persist(key(tenantA, "seed-kid")).call(s::flush)));
        // No app.tenant_id set → current_setting is NULL → RLS yields zero rows.
        asserter.assertEquals(() -> unscoped(this::countKeys), 0L);
    }
}
