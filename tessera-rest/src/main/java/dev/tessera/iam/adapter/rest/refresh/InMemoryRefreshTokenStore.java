package dev.tessera.iam.adapter.rest.refresh;

import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshReuseDetection;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory, single-node refresh-token family store — the development / Docker-free implementation
 * of both {@link RefreshTokenStorePort} and {@link RefreshTokenTenantResolverPort}, mirroring
 * {@link dev.tessera.iam.adapter.rest.authcode.InMemoryAuthorizationCodeStore}.
 *
 * <p>Families are held in a {@link ConcurrentHashMap} of immutable {@link RefreshTokenFamily}
 * snapshots. The security-critical atomicity of rotation/replay comes from
 * {@link ConcurrentMap#compute}, which runs its remapping function atomically per key: of any number
 * of concurrent redemptions of the same token, exactly one observes the current hash and rotates
 * (advancing the snapshot), and the rest observe the now-previous hash and are classified as replays
 * — the same guarantee the single-Postgres-node adapter gets from a row lock. Both ports are served
 * by one bean because the resolver and the store share the family map; a clustered deployment
 * replaces this with a shared-cache adapter whose atomic compute provides the same semantics.
 *
 * <p>Registered {@link DefaultBean} so the persistence-backed adapter supersedes it automatically in
 * the assembled server, exactly as with the client-registry and code-store adapters.
 */
@ApplicationScoped
@DefaultBean
public class InMemoryRefreshTokenStore
        implements RefreshTokenStorePort, RefreshTokenTenantResolverPort {

    private final ConcurrentMap<FamilyId, RefreshTokenFamily> families = new ConcurrentHashMap<>();

    @Override
    public Uni<Void> createFamily(RefreshTokenFamily family) {
        if (family == null) {
            throw new IllegalArgumentException("family must not be null");
        }
        families.put(family.id(), family);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<RefreshConsumeOutcome> consumeAndRotate(
            FamilyId id,
            RealmKey authoritativeRealm,
            String presentedHash,
            String newTokenHash,
            Instant now) {
        // A one-element holder to lift the decision out of the atomic remap.
        RefreshConsumeOutcome[] out = new RefreshConsumeOutcome[1];
        families.compute(id, (key, fam) -> {
            if (fam == null || !fam.realm().equals(authoritativeRealm)) {
                // Unknown id, or scoped to the wrong realm (RLS parity: invisible ⇒ no family).
                out[0] = new RefreshConsumeOutcome(new RefreshDecision.Unknown(), null);
                return fam;
            }
            RefreshDecision decision = RefreshReuseDetection.classify(fam, presentedHash, now);
            RefreshTokenFamily next = switch (decision) {
                case RefreshDecision.Rotate r -> rotate(fam, newTokenHash);
                case RefreshDecision.Replay rp -> burn(fam);
                case RefreshDecision.Unknown u -> fam;
                case RefreshDecision.Expired e -> fam;
            };
            out[0] = new RefreshConsumeOutcome(decision, next);
            return next;
        });
        return Uni.createFrom().item(out[0]);
    }

    @Override
    public Uni<Void> revokeFamily(FamilyId id, RealmKey authoritativeRealm) {
        families.computeIfPresent(id, (key, fam) ->
                fam.realm().equals(authoritativeRealm) ? burn(fam) : fam);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
        RefreshTokenFamily fam = families.get(id);
        // RLS parity: a family is visible only within its own realm.
        return Uni.createFrom().item(fam != null && fam.realm().equals(realm) ? fam : null);
    }

    @Override
    public Uni<Optional<RealmKey>> resolveOwningRealm(FamilyId id) {
        RefreshTokenFamily fam = families.get(id);
        // Header-independent: the family's own realm, regardless of any request tenant.
        return Uni.createFrom().item(Optional.ofNullable(fam).map(RefreshTokenFamily::realm));
    }

    private static RefreshTokenFamily rotate(RefreshTokenFamily fam, String newTokenHash) {
        return new RefreshTokenFamily(
                fam.id(), fam.realm(), fam.userId(), fam.clientId(),
                newTokenHash, fam.currentTokenHash(), fam.generation() + 1, false,
                fam.createdAt(), fam.expiresAt());
    }

    private static RefreshTokenFamily burn(RefreshTokenFamily fam) {
        return new RefreshTokenFamily(
                fam.id(), fam.realm(), fam.userId(), fam.clientId(),
                fam.currentTokenHash(), fam.previousTokenHash(), fam.generation(), true,
                fam.createdAt(), fam.expiresAt());
    }
}
