package dev.tessera.iam.domain.authcode;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The state bound to an issued authorization code — the payload stored, single-use, in
 * the tenant-scoped code store between {@code /authorize} and {@code /token}.
 *
 * <p>An authorization code is an opaque handle; <em>this</em> is what it stands for. The
 * token endpoint loads the grant by code, then enforces the bindings RFC 6749 §4.1.3
 * requires before issuing tokens:
 * <ul>
 *   <li>the {@code client_id} on the token request equals {@link #clientId()};</li>
 *   <li>the {@code redirect_uri} on the token request <strong>exactly</strong> equals
 *       {@link #redirectUri()} (see {@link #redirectUriMatches(String)});</li>
 *   <li>the presented {@code code_verifier} satisfies {@link #codeChallenge()} via
 *       {@link PkceVerifier};</li>
 *   <li>the code has not {@link #isExpired(Instant) expired}.</li>
 * </ul>
 * The {@code nonce} is carried so it can be bound into the issued ID token (OIDC Core
 * §3.1.3.6). Single-use (replay) protection is the store's job — it consumes the code
 * exactly once — not a field here.
 *
 * <p>Fully immutable: collections are defensively copied and the {@link Instant}s are
 * themselves immutable. The grant holds the <em>resolved</em> {@link ClientId} (the
 * client was looked up at {@code /authorize}), not the wire string.
 *
 * @param realm         the realm (tenant key) the grant belongs to (never {@code null})
 * @param clientId      the resolved client identity (never {@code null})
 * @param subjectId     the authenticated end-user {@code sub} (never {@code null} or blank)
 * @param redirectUri   the {@code redirect_uri} the code was issued against (never {@code null} or blank)
 * @param scopes        the granted scopes; defensively copied, order-preserving (never {@code null})
 * @param nonce         the OIDC {@code nonce} to bind into the ID token (never {@code null} or blank)
 * @param codeChallenge the PKCE challenge to verify at the token endpoint (never {@code null})
 * @param issuedAt      when the code was issued (never {@code null})
 * @param expiresAt     when the code expires (never {@code null}; after {@code issuedAt})
 */
public record AuthorizationGrant(
        RealmKey realm,
        ClientId clientId,
        String subjectId,
        String redirectUri,
        Set<String> scopes,
        String nonce,
        CodeChallenge codeChallenge,
        Instant issuedAt,
        Instant expiresAt) {

    public AuthorizationGrant {
        if (realm == null) {
            throw new IllegalArgumentException("AuthorizationGrant realm must not be null");
        }
        if (clientId == null) {
            throw new IllegalArgumentException("AuthorizationGrant clientId must not be null");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("AuthorizationGrant subjectId must not be blank");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("AuthorizationGrant redirectUri must not be blank");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("AuthorizationGrant scopes must not be null");
        }
        if (nonce == null || nonce.isBlank()) {
            throw new IllegalArgumentException("AuthorizationGrant nonce must not be blank");
        }
        if (codeChallenge == null) {
            throw new IllegalArgumentException("AuthorizationGrant codeChallenge must not be null");
        }
        if (issuedAt == null) {
            throw new IllegalArgumentException("AuthorizationGrant issuedAt must not be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("AuthorizationGrant expiresAt must not be null");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("AuthorizationGrant expiresAt must be after issuedAt");
        }
        scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scopes));
    }

    /**
     * Exact {@code redirect_uri} match (RFC 6749 §4.1.3): the value presented at the token
     * endpoint must be character-for-character identical to the one the code was issued
     * against. No normalisation, no prefix/substring matching — that is a deliberate
     * security property, so this is a plain {@link String#equals(Object)}.
     *
     * @param presented the {@code redirect_uri} on the token request (may be {@code null})
     * @return {@code true} iff it exactly equals the bound redirect URI
     */
    public boolean redirectUriMatches(String presented) {
        return redirectUri.equals(presented);
    }

    /**
     * @param now the current instant (threaded in — the domain reads no clock)
     * @return {@code true} iff the code has expired at {@code now}
     */
    public boolean isExpired(Instant now) {
        if (now == null) {
            throw new IllegalArgumentException("now must not be null");
        }
        return !now.isBefore(expiresAt);
    }
}
