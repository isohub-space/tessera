package dev.tessera.iam.domain.client;

import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
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
 * @param allowedScopes the scopes the client may be granted on its own behalf by the
 *                      {@code client_credentials} grant, each an RFC 6749 §3.3 scope token
 *                      (never {@code null}, may be empty)
 * @param audiences     the audiences ({@code aud}) its {@code client_credentials} tokens may name,
 *                      none blank or containing whitespace (never {@code null}, may be empty:
 *                      such a client is issued no token)
 * @param roles         the roles its {@code client_credentials} tokens carry, from its
 *                      registration; none blank or containing whitespace, because the registry
 *                      stores them whitespace-separated (never {@code null}, may be empty)
 * @param postLogoutRedirectUris registered post-logout redirect URIs (exact-match allow-list
 *                      for the end-session endpoint); defensively copied and exposed
 *                      unmodifiable (never {@code null}, may be empty)
 */
public record ConfidentialClient(
        ClientId id,
        RealmKey realm,
        Set<GrantType> allowedGrants,
        ClientAuthMethod authMethod,
        Set<String> redirectUris,
        Set<String> allowedScopes,
        Set<String> audiences,
        List<String> roles,
        Set<String> postLogoutRedirectUris) implements Client {

    /** A client with no post-logout redirect URI registered. */
    public ConfidentialClient(
            ClientId id,
            RealmKey realm,
            Set<GrantType> allowedGrants,
            ClientAuthMethod authMethod,
            Set<String> redirectUris,
            Set<String> allowedScopes,
            Set<String> audiences,
            List<String> roles) {
        this(id, realm, allowedGrants, authMethod, redirectUris, allowedScopes, audiences, roles, Set.of());
    }

    /** A client with no {@code client_credentials} scopes, audiences or roles registered. */
    public ConfidentialClient(
            ClientId id,
            RealmKey realm,
            Set<GrantType> allowedGrants,
            ClientAuthMethod authMethod,
            Set<String> redirectUris) {
        this(id, realm, allowedGrants, authMethod, redirectUris, Set.of(), Set.of(), List.of());
    }

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
        if (allowedScopes == null || audiences == null || roles == null) {
            throw new IllegalArgumentException(
                    "ConfidentialClient allowedScopes, audiences and roles must not be null");
        }
        if (postLogoutRedirectUris == null) {
            throw new IllegalArgumentException("ConfidentialClient postLogoutRedirectUris must not be null");
        }
        allowedScopes.forEach(scope -> require(isScopeToken(scope), "allowedScopes", scope));
        audiences.forEach(audience -> require(isToken(audience), "audiences", audience));
        roles.forEach(role -> require(isToken(role), "roles", role));
        // Defensive copy + unmodifiable view: the record stays immutable even if the
        // caller mutates the set it passed in.
        allowedGrants = Collections.unmodifiableSet(new HashSet<>(allowedGrants));
        redirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(redirectUris));
        allowedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(allowedScopes));
        audiences = Collections.unmodifiableSet(new LinkedHashSet<>(audiences));
        roles = List.copyOf(roles);
        postLogoutRedirectUris = Collections.unmodifiableSet(new LinkedHashSet<>(postLogoutRedirectUris));
    }

    private static void require(boolean valid, String list, String value) {
        if (!valid) {
            throw new IllegalArgumentException("ConfidentialClient " + list + " has an invalid value: " + value);
        }
    }

    /** RFC 6749 §3.3: {@code scope-token = 1*( %x21 / %x23-5B / %x5D-7E )}. */
    private static boolean isScopeToken(String scope) {
        return scope != null && !scope.isEmpty()
                && scope.chars().allMatch(c -> c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E));
    }

    /** Non-blank and free of whitespace, so it survives whitespace-separated storage. */
    private static boolean isToken(String value) {
        return value != null && !value.isEmpty() && value.chars().noneMatch(Character::isWhitespace);
    }
}
