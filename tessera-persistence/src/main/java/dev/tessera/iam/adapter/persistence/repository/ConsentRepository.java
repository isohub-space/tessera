package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.ConsentEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link ConsentEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code consent} row-level-security
 * policy scopes every read and write fail-closed.
 */
@ApplicationScoped
public class ConsentRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds the consent a user granted to a client within the tenant, if any.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param userId   the consenting user id
     * @param clientId the client the consent was granted to
     * @return a {@link Uni} emitting the consent, or {@code null} if none matches
     */
    public Uni<ConsentEntity> findByUserAndClient(UUID tenantId, UUID userId, UUID clientId) {
        return scoped.inTenant(tenantId, session ->
                session.createQuery(
                                "from ConsentEntity c where c.userId = :user "
                                        + "and c.clientId = :client",
                                ConsentEntity.class)
                        .setParameter("user", userId)
                        .setParameter("client", clientId)
                        .getSingleResultOrNull());
    }

    /**
     * Persists a new consent.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param consent  the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<ConsentEntity> persist(UUID tenantId, ConsentEntity consent) {
        return scoped.inTenant(tenantId, session -> session.persist(consent).replaceWith(consent));
    }
}
