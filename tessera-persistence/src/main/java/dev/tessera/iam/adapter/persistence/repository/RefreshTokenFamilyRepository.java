package dev.tessera.iam.adapter.persistence.repository;

import dev.tessera.iam.adapter.persistence.entity.RefreshTokenFamilyEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Tenant-scoped repository for {@link RefreshTokenFamilyEntity}.
 *
 * <p>Every operation takes the owning {@code tenantId} and routes all database access
 * through {@link TenantScopedSession#inTenant}, so the {@code refresh_token_family}
 * row-level-security policy scopes every read and write fail-closed.
 *
 * <p>The {@link #rotate} and {@link #markReused} methods support refresh-token rotation
 * with replay detection: rotation advances the family to a fresh token hash, while a
 * presented but superseded token is a replay signal that marks the family reused.
 */
@ApplicationScoped
public class RefreshTokenFamilyRepository {

    @Inject
    TenantScopedSession scoped;

    /**
     * Finds a token family by its primary key within the tenant.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the family id (a time-ordered UUID)
     * @return a {@link Uni} emitting the family, or {@code null} if none matches
     */
    public Uni<RefreshTokenFamilyEntity> findById(UUID tenantId, UUID id) {
        return scoped.inTenant(tenantId,
                session -> session.find(RefreshTokenFamilyEntity.class, id));
    }

    /**
     * Persists a new token family.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param family   the entity to persist
     * @return a {@link Uni} emitting the persisted entity
     */
    public Uni<RefreshTokenFamilyEntity> persist(UUID tenantId, RefreshTokenFamilyEntity family) {
        return scoped.inTenant(tenantId,
                session -> session.persist(family).replaceWith(family));
    }

    /**
     * Rotates a family forward: replaces its current token hash and increments its
     * generation. A no-op (emitting {@code null}) if the family does not exist.
     *
     * @param tenantId     the owning tenant (the RLS scoping key)
     * @param id           the family id
     * @param newTokenHash the hash of the freshly issued token
     * @return a {@link Uni} emitting the rotated family, or {@code null} if absent
     */
    public Uni<RefreshTokenFamilyEntity> rotate(UUID tenantId, UUID id, String newTokenHash) {
        return scoped.inTenant(tenantId, session ->
                session.find(RefreshTokenFamilyEntity.class, id)
                        .onItem().ifNotNull().invoke(family -> {
                            family.currentTokenHash = newTokenHash;
                            family.generation++;
                        }));
    }

    /**
     * Marks a family as reused (replay detected), which revokes it. A no-op (emitting
     * {@code null}) if the family does not exist.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param id       the family id
     * @return a {@link Uni} emitting the marked family, or {@code null} if absent
     */
    public Uni<RefreshTokenFamilyEntity> markReused(UUID tenantId, UUID id) {
        return scoped.inTenant(tenantId, session ->
                session.find(RefreshTokenFamilyEntity.class, id)
                        .onItem().ifNotNull().invoke(family -> family.reused = true));
    }
}
