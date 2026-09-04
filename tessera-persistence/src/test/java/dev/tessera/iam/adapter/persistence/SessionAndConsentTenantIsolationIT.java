package dev.tessera.iam.adapter.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.persistence.consent.PersistentConsentStore;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.adapter.persistence.session.PersistentSessionStore;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the requirement that "the session is tenant-scoped: a session in one realm is
 * never valid in another" — through the actual outbound ports the login/authorize flow uses
 * ({@link PersistentSessionStore}, {@link PersistentConsentStore}), not just the raw entities.
 *
 * <p>Two isolation axes are exercised, because only one of them is PostgreSQL RLS: a
 * <strong>different tenant</strong> is rejected by row-level security (the row is invisible),
 * while a <strong>different baseline within the same tenant</strong> is rejected by
 * {@link PersistentSessionStore}'s own realm check — RLS in this schema is keyed on
 * {@code tenant_id} alone, so the baseline comparison is an application-level invariant this
 * test specifically pins down (a regression that dropped it would not be caught by the
 * existing per-entity RLS ITs, which do not vary baseline while holding tenant fixed).
 *
 * <p>In the spirit of {@link NoCrossTenantLeakageIT}: real PostgreSQL, the production
 * persistence chokepoint, no fakes.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("Session & consent stores — tenant- and baseline-scoped (PostgreSQL integration)")
class SessionAndConsentTenantIsolationIT {

    private static final Instant T0 = Instant.parse("2026-06-21T08:00:00Z");

    @Inject
    PersistentSessionStore sessions;

    @Inject
    PersistentConsentStore consents;

    @Inject
    UserRepository users;

    private static RealmKey realm(UUID tenant, UUID baseline) {
        return new RealmKey(new TenantId(tenant), new BaselineId(baseline));
    }

    // -------------------------------------------------------------------------
    // Sessions
    // -------------------------------------------------------------------------

    @Test
    @RunOnVertxContext
    @DisplayName("a session created for one tenant does not resolve when looked up under another tenant")
    void sessionInvisibleAcrossTenants(UniAsserter asserter) {
        UUID baseline = UUID.randomUUID();
        RealmKey owner = realm(UUID.randomUUID(), baseline);
        RealmKey intruder = realm(UUID.randomUUID(), baseline);

        asserter.assertThat(
                () -> sessions.create(owner, "sub-owner", Duration.ofMinutes(10))
                        .flatMap(created -> sessions.find(intruder, created.id())),
                found -> assertThat(found).as("a foreign tenant must never resolve the session").isEmpty());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a session created for one baseline does not resolve under a different baseline of the SAME tenant")
    void sessionInvisibleAcrossBaselinesWithinSameTenant(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey owner = realm(tenant, UUID.randomUUID());
        RealmKey otherBaseline = realm(tenant, UUID.randomUUID());

        asserter.assertThat(
                () -> sessions.create(owner, "sub-owner", Duration.ofMinutes(10))
                        .flatMap(created -> sessions.find(otherBaseline, created.id())),
                found -> assertThat(found)
                        .as("RLS alone does not separate baselines — the store must")
                        .isEmpty());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a session resolves correctly within its OWN realm")
    void sessionResolvesWithinOwnRealm(UniAsserter asserter) {
        RealmKey owner = realm(UUID.randomUUID(), UUID.randomUUID());

        asserter.assertThat(
                () -> sessions.create(owner, "sub-owner", Duration.ofMinutes(10))
                        .flatMap(created -> sessions.find(owner, created.id())),
                found -> {
                    assertThat(found).isPresent();
                    assertThat(found.map(Session::subjectId)).contains("sub-owner");
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("an expired session no longer resolves")
    void expiredSessionDoesNotResolve(UniAsserter asserter) {
        RealmKey owner = realm(UUID.randomUUID(), UUID.randomUUID());

        // A short-lived session, given time to actually expire via a non-blocking Mutiny
        // delay (never Thread.sleep — this runs on the Vert.x event-loop context).
        asserter.assertThat(
                () -> sessions.create(owner, "sub-owner", Duration.ofMillis(50))
                        .flatMap(created -> Uni.createFrom().item(created)
                                .onItem().delayIt().by(Duration.ofMillis(300)))
                        .flatMap(created -> sessions.find(owner, created.id())),
                found -> assertThat(found).as("an expired session must not resolve").isEmpty());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("logout invalidates a session so it no longer resolves, even within its own realm")
    void logoutInvalidatesSession(UniAsserter asserter) {
        RealmKey owner = realm(UUID.randomUUID(), UUID.randomUUID());

        asserter.assertThat(
                () -> sessions.create(owner, "sub-owner", Duration.ofMinutes(10))
                        .flatMap(created -> sessions.invalidate(owner, created.id())
                                .replaceWith(created))
                        .flatMap(created -> sessions.find(owner, created.id())),
                found -> assertThat(found).isEmpty());
    }

    // -------------------------------------------------------------------------
    // Consent
    // -------------------------------------------------------------------------

    private static UserEntity user(UUID tenantId, UUID baselineId, String subject) {
        UserEntity entity = new UserEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.baselineId = baselineId;
        entity.subjectId = subject;
        entity.username = subject + "-login";
        entity.createdAt = T0;
        return entity;
    }

    @Test
    @RunOnVertxContext
    @DisplayName("a consent granted in one tenant is not visible when checked under another tenant")
    void consentInvisibleAcrossTenants(UniAsserter asserter) {
        UUID baseline = UUID.randomUUID();
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        RealmKey ownerRealm = realm(tenantA, baseline);
        RealmKey intruderRealm = realm(tenantB, baseline);
        ClientId client = ClientId.generate();

        asserter.execute(() -> users.persist(tenantA, user(tenantA, baseline, "sub-owner")));
        asserter.execute(() -> consents.grant(ownerRealm, "sub-owner", client, Set.of("openid")));

        // Under the intruding tenant there is no such user at all, so hasConsent is false —
        // the same fail-closed outcome a real cross-tenant probe would see.
        asserter.assertEquals(
                () -> consents.hasConsent(intruderRealm, "sub-owner", client, Set.of("openid")),
                Boolean.FALSE);
        asserter.assertEquals(
                () -> consents.hasConsent(ownerRealm, "sub-owner", client, Set.of("openid")),
                Boolean.TRUE);
    }
}
