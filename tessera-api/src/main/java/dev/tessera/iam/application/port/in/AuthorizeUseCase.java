package dev.tessera.iam.application.port.in;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;

/**
 * Inbound port for the authorization endpoint ({@code /authorize}) of the Authorization
 * Code + PKCE flow.
 *
 * <p>Given a validated {@link AuthorizationRequest} and the {@code sub} of the end-user
 * who has authenticated at this point in the flow, the use case validates the request
 * against the registered client (the {@code redirect_uri} must be registered, the client
 * must be allowed the code grant), mints a single-use authorization code bound to the
 * request (PKCE challenge, nonce, redirect URI, scopes), stores it tenant-scoped, and
 * returns the code to redirect back with — or an {@link AuthorizationError} describing why
 * the request was refused.
 *
 * <p>How the {@code redirect_uri} mismatch / unknown-client cases surface (a user-facing
 * error page vs an error redirect) is the adapter's call; the use case only classifies
 * the outcome.
 */
public interface AuthorizeUseCase {

    /**
     * Authorizes a request and issues a single-use code for an authenticated subject.
     *
     * @param request   the validated authorization request (never {@code null})
     * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
     * @return a {@link Uni} emitting the {@link AuthorizeResult}
     */
    Uni<AuthorizeResult> authorize(AuthorizationRequest request, String subjectId);

    /**
     * The outcome of an authorization request: a sealed pair of success (an issued code to
     * redirect with, plus the round-tripped {@code state}) or failure (an OAuth error).
     */
    sealed interface AuthorizeResult permits AuthorizeResult.Issued, AuthorizeResult.Failed {

        /**
         * Success: redirect to the request's {@code redirect_uri} with this {@code code}
         * and {@code state} (and the RFC 9207 {@code iss}).
         *
         * @param code  the issued authorization code (never {@code null} or blank)
         * @param state the {@code state} to round-trip (never {@code null} or blank)
         */
        record Issued(String code, String state) implements AuthorizeResult {
            public Issued {
                if (code == null || code.isBlank()) {
                    throw new IllegalArgumentException("Issued code must not be blank");
                }
                if (state == null || state.isBlank()) {
                    throw new IllegalArgumentException("Issued state must not be blank");
                }
            }
        }

        /**
         * Failure: the request was refused with an OAuth error. {@code redirectable} tells
         * the adapter whether the error may be sent back to the client's redirect URI
         * (RFC 6749 §4.1.2.1: only once the client and redirect URI are validated) or must
         * be shown directly to the user.
         *
         * @param error        the OAuth error code (never {@code null})
         * @param description  a non-sensitive human-readable description (never {@code null})
         * @param redirectable whether the error may be delivered via redirect
         */
        record Failed(AuthorizationError error, String description, boolean redirectable)
                implements AuthorizeResult {
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
