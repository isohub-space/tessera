package dev.tessera.iam.domain.authflow;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.List;
import java.util.Set;

/**
 * The immutable, <strong>already-fetched</strong> inputs from which a
 * {@link ClaimContributor} assembles claims.
 *
 * <p>This record is the boundary of the claim-assembly split: the slow, async work of <em>fetching</em> roles and attributes from
 * an external tenant registry happens in the shell behind the {@code ClaimSourcePort}
 * (iam-api); by the time a {@code ClaimContext} exists, all source data is in hand,
 * so deriving the token claims is a <em>pure</em> function with no I/O.
 *
 * @param subject the authenticated principal whose token is being built (never
 *               {@code null})
 * @param realm   the realm the token is issued for (never {@code null})
 * @param roles   the subject's roles, already fetched from the role source (never
 *               {@code null}; copied unmodifiable)
 * @param scopes  the granted OAuth2 scopes that gate which claims are emitted (never
 *               {@code null}; copied unmodifiable)
 */
public record ClaimContext(Subject subject, RealmKey realm, List<String> roles, Set<String> scopes) {

    public ClaimContext {
        if (subject == null) {
            throw new IllegalArgumentException("ClaimContext subject must not be null");
        }
        if (realm == null) {
            throw new IllegalArgumentException("ClaimContext realm must not be null");
        }
        if (roles == null) {
            throw new IllegalArgumentException("ClaimContext roles must not be null");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("ClaimContext scopes must not be null");
        }
        roles = List.copyOf(roles);
        scopes = Set.copyOf(scopes);
    }
}
