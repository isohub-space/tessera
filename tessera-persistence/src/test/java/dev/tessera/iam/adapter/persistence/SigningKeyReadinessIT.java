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
 * Proves the signing-key readiness verdict against a real PostgreSQL: the gate is DOWN (count of {@code ACTIVE} keys is
 * zero) when the tenant has no active key, and UP (count &gt; 0) once one exists.
 *
 * <p>The launcher's {@code SigningKeyReadinessCheck} is config-disabled under
 * {@code %test} (no datasource in the Docker-free launcher tests), so the DB-backed
 * behaviour it relies on is verified here, where Testcontainers provides a Postgres.
 * This exercises the exact same tenant-scoped {@code count(...)} query the check
 * issues — the GUC is set on the connection, then ACTIVE {@code signing_key} rows are
 * counted — so the readiness verdict ({@code count > 0}) is proven both ways.</p>
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("IAM signing-key readiness — DOWN when no ACTIVE key, UP once one exists")
class SigningKeyReadinessIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    @Inject
    Mutiny.SessionFactory sessionFactory;

    private <T> Uni<T> scoped(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return sessionFactory.withTransaction((session, tx) -> session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult()
                .chain(() -> work.apply(session)));
    }

    /** The verdict the readiness check computes: count of ACTIVE keys for the tenant. */
    private Uni<Long> activeKeyCount(Mutiny.Session session) {
        return session
                .createQuery(
                        "select count(k) from SigningKeyEntity k where k.state = :state",
                        Long.class)
                .setParameter("state", SigningKeyState.ACTIVE)
                .getSingleResult();
    }

    private static SigningKeyEntity activeKey(UUID tenantId) {
        SigningKeyEntity entity = new SigningKeyEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.kid = "ready-kid";
        entity.algorithm = "EdDSA";
        entity.state = SigningKeyState.ACTIVE;
        entity.publicJwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"ready\"}";
        entity.createdAt = T0;
        return entity;
    }

    @Test
    @RunOnVertxContext
    @DisplayName("no ACTIVE key → readiness verdict is DOWN (count == 0)")
    void downWhenNoActiveKey(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        // Empty table for this tenant → the gate would report DOWN.
        asserter.assertEquals(() -> scoped(tenant, this::activeKeyCount), 0L);
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an ACTIVE key present → readiness verdict is UP (count > 0)")
    void upWhenActiveKeyPresent(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        asserter.execute(() -> scoped(tenant, s -> s.persist(activeKey(tenant)).call(s::flush)));
        asserter.assertEquals(() -> scoped(tenant, this::activeKeyCount), 1L);
    }
}
