package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.CredentialEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link CredentialEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code iam_credential}
 * row-level-security policy scopes every read and write fail-closed: a transaction with
 * no tenant bound sees nothing and may write nothing.
 */
@ApplicationScoped
public class CredentialRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Lists all credentials owned by a user within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param userId   the owning user id
     * @return a {@link Uni} emitting the user's credentials (possibly empty)
     */
    public Uni<List<CredentialEntity>> findByUser(UUID tenantId, UUID userId) {
        return scoped.inTenant(tenantId, session ->
                session.createQuery(
                                "from CredentialEntity c where c.userId = :user",
                                CredentialEntity.class)
                        .setParameter("user", userId)
                        .getResultList());
    }

    /**
     * Persists a new credential.
     *
     * @param tenantId   the owning tenant (the RLS scoping key)
     * @param credential the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<CredentialEntity> persist(UUID tenantId, CredentialEntity credential) {
        return scoped.inTenant(tenantId,
                session -> session.persist(credential).replaceWith(credential));
    }
}
