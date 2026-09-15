package dev.tessera.iam.adapter.persistence.session;

import dev.tessera.iam.adapter.persistence.entity.AuthSessionEntity;
import dev.tessera.iam.adapter.persistence.repository.AuthSessionRepository;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence-backed {@link SessionStorePort}, backed by the {@code auth_session} table via
 * {@link AuthSessionRepository}.
 *
 * <p>{@link #find} enforces the tenant-scoping invariant end to end: the lookup itself is
 * row-level-security-scoped to {@code realm.tenant()} (a session belonging to another tenant
 * simply is not visible to the query — {@code null}, indistinguishable from "no such
 * session"), and on top of that this adapter re-checks the row's own {@code baseline_id}
 * against the caller's realm (RLS alone only isolates by {@code tenant_id}, not by baseline)
 * and its expiry. Any of the three makes it a miss.
 */
@ApplicationScoped
public class PersistentSessionStore implements SessionStorePort {

    /** Lifecycle state once a session is established (this adapter never creates a pending one). */
    private static final String STATE_AUTHENTICATED = "AUTHENTICATED";

    /** Lifecycle state after logout / invalidation. */
    private static final String STATE_REVOKED = "REVOKED";

    @Inject
    AuthSessionRepository sessions;

    private final Clock clock;

    /** CDI requires a no-arg constructor; uses the system UTC clock. */
    public PersistentSessionStore() {
        this(Clock.systemUTC());
    }

    /** Visible for testing: inject a fixed clock to exercise expiry deterministically. */
    public PersistentSessionStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Uni<Session> create(RealmKey realm, String subjectId, Duration ttl) {
        if (realm == null || subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("realm and subjectId must not be blank");
        }
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        Instant now = clock.instant();
        Instant expiresAt = now.plus(ttl);

        AuthSessionEntity entity = new AuthSessionEntity();
        entity.id = SessionId.generate().value();
        entity.tenantId = realm.tenant().value();
        entity.baselineId = realm.baseline().value();
        entity.subjectId = subjectId;
        entity.state = STATE_AUTHENTICATED;
        entity.createdAt = now;
        entity.expiresAt = expiresAt;

        return sessions.persist(realm.tenant().value(), entity)
                .map(saved -> new Session(realm, new SessionId(saved.id), subjectId, now, expiresAt));
    }

    @Override
    public Uni<Optional<Session>> find(RealmKey realm, SessionId id) {
        if (realm == null || id == null) {
            throw new IllegalArgumentException("realm and id must not be null");
        }
        return sessions.findById(realm.tenant().value(), id.value())
                .map(entity -> toSession(realm, entity));
    }

    @Override
    public Uni<Void> invalidate(RealmKey realm, SessionId id) {
        if (realm == null || id == null) {
            throw new IllegalArgumentException("realm and id must not be null");
        }
        return sessions.updateState(realm.tenant().value(), id.value(), STATE_REVOKED);
    }

    private Optional<Session> toSession(RealmKey realm, AuthSessionEntity entity) {
        if (entity == null) {
            return Optional.empty();
        }
        // Belt-and-braces: RLS scopes the row-level-security policy by tenant_id only, so
        // also require the baseline to match the caller's realm, and the session to be
        // AUTHENTICATED (never REVOKED), and unexpired, all fail-closed to a miss.
        UUID callerBaseline = realm.baseline().value();
        if (!callerBaseline.equals(entity.baselineId)
                || !STATE_AUTHENTICATED.equals(entity.state)
                || entity.subjectId == null
                || entity.expiresAt == null
                || !clock.instant().isBefore(entity.expiresAt)) {
            return Optional.empty();
        }
        return Optional.of(new Session(
                realm, new SessionId(entity.id), entity.subjectId, entity.createdAt, entity.expiresAt));
    }
}
