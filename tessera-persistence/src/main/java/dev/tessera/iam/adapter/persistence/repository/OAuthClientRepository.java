package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link OAuthClientEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code oauth_client}
 * row-level-security policy scopes every read and write fail-closed.
 */
@ApplicationScoped
public class OAuthClientRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds a client by its external {@code client_key} within the tenant.
     *
     * @param tenantId  the owning tenant (the RLS scoping key)
     * @param clientKey the external client identifier to match
     * @return a {@link Uni} emitting the client, or {@code null} if none matches
     */
    public Uni<OAuthClientEntity> findByClientKey(UUID tenantId, String clientKey) {
        return scoped.inTenant(tenantId, session ->
                session.createQuery(
                                "from OAuthClientEntity c where c.clientKey = :key",
                                OAuthClientEntity.class)
                        .setParameter("key", clientKey)
                        .getSingleResultOrNull());
    }

    /**
     * Finds a client by its primary key within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the client id
     * @return a {@link Uni} emitting the client, or {@code null} if none matches
     */
    public Uni<OAuthClientEntity> findById(UUID tenantId, UUID id) {
        return scoped.inTenant(tenantId, session -> session.find(OAuthClientEntity.class, id));
    }

    /**
     * Persists a new client.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param client   the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<OAuthClientEntity> persist(UUID tenantId, OAuthClientEntity client) {
        return scoped.inTenant(tenantId, session -> session.persist(client).replaceWith(client));
    }
}
