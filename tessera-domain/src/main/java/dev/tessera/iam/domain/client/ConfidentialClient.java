package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A confidential client — one that can safely hold credentials and authenticates
 * to the token endpoint.
 *
 * <p>Carries a {@link ClientAuthMethod}; there is no {@code NONE} option (see that
 * enum). The secret/key material itself is <strong>not</strong> in the domain —
 * only the <em>method</em> by which the shell will verify it.
 *
 * @param id            stable internal identity (never {@code null})
 * @param realm         owning realm/tenant key (never {@code null})
 * @param allowedGrants permitted grants; defensively copied and exposed unmodifiable
 *                      (never {@code null} or empty)
 * @param authMethod    how this client authenticates (never {@code null})
 * @param redirectUris  registered redirect URIs (exact-match allow-list); defensively
 *                      copied and exposed unmodifiable (never {@code null}, may be empty)
 */
public record ConfidentialClient(
        ClientId id,
        RealmKey realm,
        Set<GrantType> allowedGrants,
        ClientAuthMethod authMethod,
        Set<String> redirectUris) implements Client {

    public ConfidentialClient {
        if (id == null) {
            throw new IllegalArgumentException("ConfidentialClient id must not be null");
        }
        if (realm == null) {
            throw new IllegalArgumentException("ConfidentialClient realm must not be null");
        }
        if (allowedGrants == null || allowedGrants.isEmpty()) {
            throw new IllegalArgumentException("ConfidentialClient allowedGrants must not be empty");
        }
        if (authMethod == null) {
            throw new IllegalArgumentException("ConfidentialClient authMethod must not be null");
        }
        if (redirectUris == null) {
            throw new IllegalArgumentException("ConfidentialClient redirectUris must not be null");
        }
        // Defensive copy + unmodifiable view: the record stays immutable even if the
        // caller mutates the set it passed in.
        allowedGrants = Collections.unmodifiableSet(new HashSet<>(allowedGrants));
        redirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(redirectUris));
    }
}
