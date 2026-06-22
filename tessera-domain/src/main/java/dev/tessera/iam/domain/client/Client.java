package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Set;

/**
 * A registered OAuth2/OIDC client.
 *
 * <p>Sealed into exactly two kinds, replacing Keycloak's mutable {@code ClientModel}
 * with an immutable, type-distinguished pair:
 * <ul>
 *   <li>{@link ConfidentialClient} — can hold credentials and authenticates to the
 *       token endpoint via a {@link ClientAuthMethod};</li>
 *   <li>{@link PublicClient} — cannot keep a secret, so it is PKCE-S256 + DPoP-bound
 *       <em>by construction</em> (no secret field exists to misuse).</li>
 * </ul>
 *
 * <p>The split being sealed lets the token/auth pipeline switch exhaustively over
 * client kind with no {@code default} branch.
 */
public sealed interface Client permits ConfidentialClient, PublicClient {

    /** Stable internal identity of this client. */
    ClientId id();

    /** The realm (tenant key) this client is registered in. */
    RealmKey realm();

    /**
     * The grant types this client is permitted to use.
     *
     * <p>Returned as an unmodifiable, defensively-copied set; the WON'T-list grants
     * are unrepresentable by {@link GrantType}'s sealing.
     *
     * @return an immutable view of the allowed grants
     */
    Set<GrantType> allowedGrants();
}
