package dev.tessera.iam.domain.authcode;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A validated OAuth 2.0 / OIDC authorization request (RFC 6749 §4.1.1) for the
 * Authorization Code flow.
 *
 * <p>This is the parsed, structurally-valid form of the {@code GET/POST /authorize}
 * query: the adapter shell parses the raw query parameters and constructs this record,
 * whose compact constructor enforces the protocol invariants this server requires —
 * most importantly that PKCE is present (a {@link CodeChallenge} is non-optional, and
 * {@link CodeChallenge} can only be {@code S256}). A request that omits PKCE is therefore
 * <em>unrepresentable</em>.
 *
 * <p>The {@code clientId} here is the <em>wire</em> {@code client_id} string the client
 * presented; resolving it to a registered {@link dev.tessera.iam.domain.client.Client}
 * (and confirming the {@code redirect_uri} is registered) is an adapter/application
 * concern. The {@code redirectUri} is carried verbatim so the token endpoint can later
 * require an <strong>exact</strong> match (RFC 6749 §4.1.3) — no normalisation happens
 * in the domain.
 *
 * @param realm         the realm (tenant key) the request runs within (never {@code null})
 * @param clientId      the wire {@code client_id} (never {@code null} or blank)
 * @param redirectUri   the requested {@code redirect_uri}, verbatim (never {@code null} or blank)
 * @param scopes        the requested scopes; defensively copied, order-preserving
 *                      (never {@code null}; must contain {@code openid} for an OIDC request)
 * @param state         the opaque {@code state} to round-trip back (never {@code null} or blank)
 * @param nonce         the OIDC {@code nonce} bound into the issued ID token (never {@code null} or blank)
 * @param codeChallenge the PKCE challenge — mandatory by construction (never {@code null})
 */
public record AuthorizationRequest(
        RealmKey realm,
        String clientId,
        String redirectUri,
        Set<String> scopes,
        String state,
        String nonce,
        CodeChallenge codeChallenge) {

    public AuthorizationRequest {
        if (realm == null) {
            throw new IllegalArgumentException("AuthorizationRequest realm must not be null");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("AuthorizationRequest clientId must not be blank");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("AuthorizationRequest redirectUri must not be blank");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("AuthorizationRequest scopes must not be null");
        }
        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException("AuthorizationRequest state must not be blank");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("AuthorizationRequest nonce must not be blank");
        }
        if (codeChallenge == null) {
            // PKCE is mandatory; a request with no challenge cannot exist.
            throw new IllegalArgumentException("AuthorizationRequest requires a PKCE code challenge");
        }
        scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
    }

    /** @return {@code true} if {@code openid} was requested (an OIDC request). */
    public boolean isOpenIdRequest() {
        return scopes.contains("openid");
    }
}
