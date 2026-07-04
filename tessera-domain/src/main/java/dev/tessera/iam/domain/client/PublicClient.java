package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A public client — one that cannot keep a secret (SPAs, native apps)
 *.
 *
 * <p>There is <strong>no secret field</strong> and no {@link ClientAuthMethod}:
 * the design makes a public client PKCE-S256 + DPoP-bound <em>by construction</em>,
 * so the type itself precludes a "public client with a secret" mistake.
 *
 * @param id            stable internal identity (never {@code null})
 * @param realm         owning realm/tenant key (never {@code null})
 * @param allowedGrants permitted grants; defensively copied and exposed unmodifiable
 *                      (never {@code null} or empty)
 * @param redirectUris  registered redirect URIs (exact-match allow-list); defensively
 *                      copied and exposed unmodifiable (never {@code null}, may be empty)
 */
public record PublicClient(
        ClientId id,
        RealmKey realm,
        Set<GrantType> allowedGrants,
        Set<String> redirectUris) implements Client {

    public PublicClient {
        if (id == null) {
            throw new IllegalArgumentException("PublicClient id must not be null");
        }
        if (realm == null) {
            throw new IllegalArgumentException("PublicClient realm must not be null");
        }
        if (allowedGrants == null || allowedGrants.isEmpty()) {
            throw new IllegalArgumentException("PublicClient allowedGrants must not be empty");
        }
        if (redirectUris == null) {
            throw new IllegalArgumentException("PublicClient redirectUris must not be null");
        }
        // Defensive copy + unmodifiable view: the record stays immutable even if the
        // caller mutates the set it passed in.
        allowedGrants = Collections.unmodifiableSet(new HashSet<>(allowedGrants));
        redirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(redirectUris));
    }
}
