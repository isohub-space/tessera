package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.authflow.ClaimContext;
import dev.tessera.iam.domain.authflow.Subject;
import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * Outbound port that fetches the source data from which token claims are assembled
 *.
 *
 * <p>This is the <strong>async half</strong> of the claim-mapping split. The pure derivation of claims lives in the domain
 * ({@code dev.tessera.iam.domain.authflow.ClaimContributor}); the slow, I/O-bound work
 * of <em>fetching</em> a subject's roles and attributes — from an external tenant registry, which
 * stays the role <em>source</em> of record — lives here, behind a driven port that
 * may return {@link Uni}. The platform's reactive-hexagon convention
 * permits {@code Uni}/{@code Multi} on driven ports, and this is the
 * <em>only</em> place in the IAM functional core where reactivity is allowed:
 * the domain stays pure {@code java..}.
 *
 * <p>Intended use by the shell: call {@link #loadClaimContext} (async), then pass the
 * resolved, already-fetched {@link ClaimContext} into the pure {@code ClaimContributor}
 * — so no {@code Uni}-returning "protocol mapper" ever mutates a token builder inside
 * the core.
 *
 * <p>Implementations <strong>must</strong> resolve roles within the supplied
 * {@link RealmKey}'s tenant scope (RLS fail-closed) and never leak another tenant's
 * roles.
 */
public interface ClaimSourcePort {

    /**
     * Fetches the subject's roles and attributes for the given realm and granted
     * scopes, assembling them into an already-fetched {@link ClaimContext} ready for
     * pure claim contribution.
     *
     * @param subject the authenticated principal whose claims are being sourced
     * @param realm   the realm (tenant key) to resolve roles within (RLS-scoped)
     * @param scopes  the granted OAuth2 scopes (space-delimited values), gating which
     *               attributes are fetched
     * @return a {@link Uni} emitting the assembled, already-fetched {@link ClaimContext}
     */
    Uni<ClaimContext> loadClaimContext(Subject subject, RealmKey realm, java.util.Set<String> scopes);
}
