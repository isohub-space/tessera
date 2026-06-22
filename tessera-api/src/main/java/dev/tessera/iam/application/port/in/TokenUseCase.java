package dev.tessera.iam.application.port.in;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * Inbound port for the token endpoint ({@code /token}) of the Authorization Code + PKCE
 * flow ({@code grant_type=authorization_code}).
 *
 * <p>The use case consumes the single-use authorization code (exactly once), then enforces
 * the RFC 6749 §4.1.3 bindings before issuing tokens: the {@code client_id} matches the
 * code's client and authenticates (Argon2id, off-loop, for confidential clients); the
 * {@code redirect_uri} <strong>exactly</strong> matches; and the PKCE {@code code_verifier}
 * satisfies the stored S256 challenge. On success it issues a signed RFC 9068 access token
 * (and, for an {@code openid} request, an ID token binding the nonce); on any failure it
 * returns an {@link AuthorizationError} (collapsed to {@code invalid_grant} where RFC 6749
 * requires, so a client cannot probe which check failed).
 */
public interface TokenUseCase {

    /**
     * Redeems an authorization code for tokens.
     *
     * @param command the token request (never {@code null})
     * @return a {@link Uni} emitting the {@link TokenResult}
     */
    Uni<TokenResult> redeemAuthorizationCode(TokenRequestCommand command);

    /**
     * A parsed token request for the {@code authorization_code} grant.
     *
     * @param realm        the realm (tenant key) the request runs within (never {@code null})
     * @param code         the authorization code being redeemed (never {@code null} or blank)
     * @param redirectUri  the {@code redirect_uri} (must exactly match the code's) (never blank)
     * @param clientId     the wire {@code client_id} (never {@code null} or blank)
     * @param clientSecret the presented client secret for a confidential client, or
     *                     {@code null} for a public (PKCE-only) client
     * @param codeVerifier the PKCE {@code code_verifier} (never {@code null} or blank)
     */
    record TokenRequestCommand(
            RealmKey realm,
            String code,
            String redirectUri,
            String clientId,
            String clientSecret,
            String codeVerifier) {

        public TokenRequestCommand {
            if (realm == null) {
                throw new IllegalArgumentException("TokenRequestCommand realm must not be null");
            }
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException("TokenRequestCommand code must not be blank");
            }
            if (redirectUri == null || redirectUri.isBlank()) {
                throw new IllegalArgumentException("TokenRequestCommand redirectUri must not be blank");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("TokenRequestCommand clientId must not be blank");
            }
            if (codeVerifier == null || codeVerifier.isBlank()) {
                throw new IllegalArgumentException("TokenRequestCommand codeVerifier must not be blank");
            }
        }
    }

    /**
     * The outcome of a token request: a sealed pair of success (the issued tokens) or
     * failure (an OAuth error per RFC 6749 §5.2).
     */
    sealed interface TokenResult permits TokenResult.Issued, TokenResult.Failed {

        /**
         * Success: a signed RFC 9068 access token, its lifetime, and (for an OIDC request)
         * a signed ID token.
         *
         * @param accessToken   the compact-serialised JWT access token (never {@code null} or blank)
         * @param idToken       the compact-serialised ID token, or {@code null} for a non-OIDC request
         * @param expiresInSecs the access token lifetime in seconds (positive)
         * @param scope         the granted scope, space-delimited (never {@code null})
         */
        record Issued(String accessToken, String idToken, long expiresInSecs, String scope)
                implements TokenResult {
            public Issued {
                if (accessToken == null || accessToken.isBlank()) {
                    throw new IllegalArgumentException("Issued accessToken must not be blank");
                }
                if (expiresInSecs <= 0) {
                    throw new IllegalArgumentException("Issued expiresInSecs must be positive");
                }
                if (scope == null) {
                    throw new IllegalArgumentException("Issued scope must not be null");
                }
            }
        }

        /**
         * Failure: the request was refused with an OAuth error.
         *
         * @param error       the OAuth error code (never {@code null})
         * @param description a non-sensitive human-readable description (never {@code null})
         */
        record Failed(AuthorizationError error, String description) implements TokenResult {
            public Failed {
                if (error == null) {
                    throw new IllegalArgumentException("Failed error must not be null");
                }
                if (description == null) {
                    throw new IllegalArgumentException("Failed description must not be null");
                }
            }
        }
    }
}
