package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Outbound port that resolves the <strong>authoritative</strong> realm owning a refresh-token
 * family, from server-stored state, <em>without</em> a tenant already bound and <em>without</em>
 * trusting any request header.
 *
 * <p>This is the one deliberate exception to the header-driven tenant model: a replayed or stolen
 * refresh token must be detected and its family revoked even if the caller sends a wrong or absent
 * tenant header, so the family's own stored tenant is the source of truth. The backing adapter
 * performs a narrow, RLS-bypassing lookup that returns <em>only</em> the owning
 * {@code (tenant, baseline)} for a family id — never token material, user, scope, or any other
 * data.
 *
 * <p>Trust rules the application enforces on the result (documented here so adapters are not tempted
 * to widen the port): the resolved realm may drive <strong>revocation</strong> (fail-safe) of a
 * family in its own tenant, but token <strong>issuance</strong> remains fail-closed in the header
 * direction — a new token is minted only when the request's header tenant equals this authoritative
 * realm. Introspection must never use this resolver, so it cannot leak across tenants.
 */
public interface RefreshTokenTenantResolverPort {

    /**
     * Resolves the realm that owns a family, header-independently.
     *
     * @param id the family id parsed from a presented token (never {@code null})
     * @return a {@link Uni} emitting the owning realm, or empty if the id is unknown
     */
    Uni<Optional<RealmKey>> resolveOwningRealm(FamilyId id);
}
