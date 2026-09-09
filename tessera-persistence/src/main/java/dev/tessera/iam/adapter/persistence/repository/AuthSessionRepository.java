package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.AuthSessionEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link AuthSessionEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code auth_session}
 * row-level-security policy scopes every read and write fail-closed.
 */
@ApplicationScoped
public class AuthSessionRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds an authorization session by its primary key within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the session id (a time-ordered UUID)
     * @return a {@link Uni} emitting the session, or {@code null} if none matches
     */
    public Uni<AuthSessionEntity> findById(UUID tenantId, UUID id) {
        return scoped.inTenant(tenantId, session -> session.find(AuthSessionEntity.class, id));
    }

    /**
     * Persists a new authorization session.
     *
     * @param tenantId    the owning tenant (the RLS scoping key)
     * @param authSession the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<AuthSessionEntity> persist(UUID tenantId, AuthSessionEntity authSession) {
        return scoped.inTenant(tenantId,
                session -> session.persist(authSession).replaceWith(authSession));
    }

    /**
     * Updates the lifecycle {@code state} of a session within the tenant (e.g. ending it on
     * logout). A no-op — not an error — if no such session exists in this tenant, so callers
     * can invalidate idempotently without a prior existence check.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the session id
     * @param state    the new lifecycle state
     * @return a {@link Uni} completing once the update (if any) is applied
     */
    public Uni<Void> updateState(UUID tenantId, UUID id, String state) {
        return scoped.inTenant(tenantId, session ->
                session.find(AuthSessionEntity.class, id).invoke(entity -> {
                    if (entity != null) {
                        // A managed entity: the field change is picked up by dirty checking
                        // and flushed when the enclosing transaction commits — no explicit
                        // persist/merge call needed.
                        entity.state = state;
                    }
                }).replaceWithVoid());
    }
}
