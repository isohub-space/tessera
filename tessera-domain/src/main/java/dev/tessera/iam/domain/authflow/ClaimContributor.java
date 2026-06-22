package dev.tessera.iam.domain.authflow;

import dev.tessera.iam.domain.token.ClaimSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure assembly of token claims from already-fetched data
 *.
 *
 * <p>This is the <em>pure half</em> of the claim-mapping split this design calls out
 *: Keycloak's protocol-mapper SPI is replaced by a plain
 * deterministic function {@link #contribute(ClaimSet, ClaimContext)} that derives
 * claims over data already in hand. There is <strong>no I/O here</strong> — the
 * async fetch of the source data (roles, attributes) lives behind the
 * {@code ClaimSourcePort} in iam-api, so no {@code Uni}-returning mapper ever mutates
 * a token builder inside the core.
 *
 * <p>{@code contribute} is non-destructive: it takes an existing {@link ClaimSet}
 * (e.g. protocol-mandatory claims the shell pre-seeded) and returns a <em>new</em>
 * {@code ClaimSet} with the derived claims merged in. The input is never mutated.
 *
 * <p>A {@code ClaimContributor} is stateless; a single instance is thread-safe.
 */
public final class ClaimContributor {

    /**
     * Derives claims from the context and merges them onto an existing claim set.
     *
     * <p>Deterministic: the same {@code existing} and {@code context} always yield an
     * equal result. Currently emits {@code sub}, the {@code roles} claim, and — when
     * the {@code profile} scope is granted — a {@code realm} correlation claim.
     *
     * @param existing the claims to build upon (never {@code null})
     * @param context  the already-fetched inputs (never {@code null})
     * @return a new {@link ClaimSet} with the contributed claims merged in
     */
    public ClaimSet contribute(ClaimSet existing, ClaimContext context) {
        if (existing == null) {
            throw new IllegalArgumentException("contribute existing must not be null");
        }
        if (context == null) {
            throw new IllegalArgumentException("contribute context must not be null");
        }

        // Start from a mutable copy of the existing claims, then layer derived ones.
        Map<String, Object> merged = new LinkedHashMap<>(existing.claims());

        // The subject is always asserted.
        merged.put("sub", context.subject().subjectId());

        // Roles are stamped from already-fetched data (IAM never authors them).
        merged.put("roles", List.copyOf(context.roles()));

        // Scope-gated claim: only emit the realm correlation when 'profile' is granted.
        if (context.scopes().contains("profile")) {
            merged.put("realm_tenant", context.realm().tenant().value().toString());
            merged.put("realm_baseline", context.realm().baseline().value().toString());
        }

        // ClaimSet defensively copies + freezes the map on construction.
        return new ClaimSet(merged);
    }
}
