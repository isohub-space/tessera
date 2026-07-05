package dev.tessera.iam.adapter.persistence.refresh;

import dev.tessera.iam.adapter.persistence.entity.RefreshTokenFamilyEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshReuseDetection;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.UUID;

/**
 * Persistence-backed {@link RefreshTokenStorePort}: rotating refresh-token families on PostgreSQL
 * with fail-closed row-level security.
 *
 * <p>The security-critical single-use rotation is a <strong>conditional compare-and-swap</strong>,
 * not a read-modify-write: {@link #consumeAndRotate} issues one {@code UPDATE … WHERE
 * current_token_hash = :presented AND reused = false} whose row lock serialises concurrent
 * redemptions, so exactly one wins (rotates) and the rest observe the superseded hash and are
 * classified as replays. This replaces the earlier non-atomic {@code find}-then-mutate, which was a
 * lost-update race under concurrent refresh. Everything runs through
 * {@link TenantScopedSession#inTenant}, so RLS scopes the family to its authoritative realm.
 *
 * <p>Like {@code DbClientRepositoryAdapter}, this plain {@code @ApplicationScoped} bean supersedes
 * the fail-closed in-memory {@code @DefaultBean} in the assembled server.
 */
@ApplicationScoped
public class DbRefreshTokenStore implements RefreshTokenStorePort {

    private static final String CAS_ROTATE =
            "UPDATE refresh_token_family"
                    + " SET previous_token_hash = current_token_hash,"
                    + "     current_token_hash = :newHash,"
                    + "     generation = generation + 1"
                    + " WHERE id = :id"
                    + "   AND current_token_hash = :presented"
                    + "   AND reused = false"
                    + "   AND (expires_at IS NULL OR expires_at > :now)";

    private static final String BURN =
            "UPDATE refresh_token_family"
                    + " SET reused = true, revoked_at = COALESCE(revoked_at, :now)"
                    + " WHERE id = :id";

    private static final String INSERT_DIRECTORY =
            "INSERT INTO refresh_family_directory (family_id, tenant_id, baseline_id)"
                    + " VALUES (:fid, :tid, :bid)";

    @Inject
    TenantScopedSession scoped;

    @Override
    public Uni<Void> createFamily(RefreshTokenFamily family) {
        if (family == null) {
            throw new IllegalArgumentException("family must not be null");
        }
        UUID tenant = family.realm().tenant().value();
        UUID baseline = family.realm().baseline().value();
        RefreshTokenFamilyEntity entity = toEntity(family);
        return scoped.inTenant(tenant, session ->
                session.persist(entity)
                        .call(() -> session.createNativeQuery(INSERT_DIRECTORY)
                                .setParameter("fid", family.id().value())
                                .setParameter("tid", tenant)
                                .setParameter("bid", baseline)
                                .executeUpdate())
                        .replaceWithVoid());
    }

    @Override
    public Uni<RefreshConsumeOutcome> consumeAndRotate(
            FamilyId id, RealmKey authoritativeRealm, String presentedHash, String newTokenHash,
            Instant now) {
        if (id == null || authoritativeRealm == null) {
            throw new IllegalArgumentException("id and authoritativeRealm must not be null");
        }
        UUID tenant = authoritativeRealm.tenant().value();
        return scoped.inTenant(tenant, session ->
                session.createNativeQuery(CAS_ROTATE)
                        .setParameter("newHash", newTokenHash)
                        .setParameter("id", id.value())
                        .setParameter("presented", presentedHash)
                        .setParameter("now", now)
                        .executeUpdate()
                        // Re-read the (post-update) row in the same transaction and classify.
                        .flatMap(rowCount -> session.find(RefreshTokenFamilyEntity.class, id.value())
                                .flatMap(entity -> {
                                    if (entity == null) {
                                        // Unknown id, or invisible under this realm (RLS).
                                        return Uni.createFrom().item(new RefreshConsumeOutcome(
                                                new RefreshDecision.Unknown(), null));
                                    }
                                    RefreshTokenFamily snap = toSnapshot(entity);
                                    if (rowCount == 1) {
                                        // The CAS won: this transaction rotated the family.
                                        return Uni.createFrom().item(new RefreshConsumeOutcome(
                                                new RefreshDecision.Rotate(id), snap));
                                    }
                                    // The CAS matched nothing — classify the presented token.
                                    RefreshDecision decision =
                                            RefreshReuseDetection.classify(snap, presentedHash, now);
                                    if (decision instanceof RefreshDecision.Replay) {
                                        return burn(session, id, now).replaceWith(
                                                new RefreshConsumeOutcome(decision, snap));
                                    }
                                    if (decision instanceof RefreshDecision.Rotate) {
                                        // Defensive: a losing CAS must never issue. A Rotate here
                                        // could only arise from a concurrent external rotation racing
                                        // the re-read; treat it as a miss rather than mint a token.
                                        decision = new RefreshDecision.Unknown();
                                    }
                                    return Uni.createFrom().item(
                                            new RefreshConsumeOutcome(decision, snap));
                                })));
    }

    @Override
    public Uni<Void> revokeFamily(FamilyId id, RealmKey authoritativeRealm) {
        if (id == null || authoritativeRealm == null) {
            throw new IllegalArgumentException("id and authoritativeRealm must not be null");
        }
        return scoped.inTenant(authoritativeRealm.tenant().value(),
                session -> burn(session, id, Instant.now()).replaceWithVoid());
    }

    @Override
    public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
        if (id == null || realm == null) {
            throw new IllegalArgumentException("id and realm must not be null");
        }
        return scoped.inTenant(realm.tenant().value(),
                session -> session.find(RefreshTokenFamilyEntity.class, id.value())
                        .map(entity -> entity == null ? null : toSnapshot(entity)));
    }

    private static Uni<Integer> burn(
            org.hibernate.reactive.mutiny.Mutiny.Session session, FamilyId id, Instant now) {
        return session.createNativeQuery(BURN)
                .setParameter("now", now)
                .setParameter("id", id.value())
                .executeUpdate();
    }

    private static RefreshTokenFamilyEntity toEntity(RefreshTokenFamily family) {
        RefreshTokenFamilyEntity e = new RefreshTokenFamilyEntity();
        e.id = family.id().value();
        e.tenantId = family.realm().tenant().value();
        e.baselineId = family.realm().baseline().value();
        e.userId = UUID.fromString(family.userId());
        e.clientId = family.clientId().value();
        e.currentTokenHash = family.currentTokenHash();
        e.previousTokenHash = family.previousTokenHash();
        e.generation = family.generation();
        e.reused = family.reused();
        e.revokedAt = null;
        e.createdAt = family.createdAt();
        e.expiresAt = family.expiresAt();
        return e;
    }

    // The snapshot's realm is reconstructed from the row's own tenant_id/baseline_id, never the
    // caller-supplied realm, so a read whose tenant matches but baseline differs cannot mis-stamp it.
    private static RefreshTokenFamily toSnapshot(RefreshTokenFamilyEntity e) {
        RealmKey realm = new RealmKey(new TenantId(e.tenantId), new BaselineId(e.baselineId));
        return new RefreshTokenFamily(
                new FamilyId(e.id), realm, e.userId.toString(), new ClientId(e.clientId),
                e.currentTokenHash, e.previousTokenHash, e.generation, e.reused,
                e.createdAt, e.expiresAt);
    }
}
