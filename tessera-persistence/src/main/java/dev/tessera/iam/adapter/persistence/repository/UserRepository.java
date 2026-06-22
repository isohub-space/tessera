package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link UserEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code iam_user} row-level-security
 * policy scopes every read and write fail-closed: a transaction with no tenant bound
 * sees nothing and may write nothing.
 */
@ApplicationScoped
public class UserRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds a user by its stable OIDC {@code sub} within the tenant.
     *
     * @param tenantId  the owning tenant (the RLS scoping key)
     * @param subjectId the stable {@code sub} to match
     * @return a {@link Uni} emitting the user, or {@code null} if none matches
     */
    public Uni<UserEntity> findBySubject(UUID tenantId, String subjectId) {
        return scoped.inTenant(tenantId, session ->
                session.createQuery(
                                "from UserEntity u where u.subjectId = :sub", UserEntity.class)
                        .setParameter("sub", subjectId)
                        .getSingleResultOrNull());
    }

    /**
     * Finds a user by its primary key within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the user id
     * @return a {@link Uni} emitting the user, or {@code null} if none matches
     */
    public Uni<UserEntity> findById(UUID tenantId, UUID id) {
        return scoped.inTenant(tenantId, session -> session.find(UserEntity.class, id));
    }

    /**
     * Persists a new user.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param user     the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<UserEntity> persist(UUID tenantId, UserEntity user) {
        return scoped.inTenant(tenantId, session -> session.persist(user).replaceWith(user));
    }
}
