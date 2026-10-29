package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Inbound port for the end-session endpoint (OpenID Connect RP-Initiated Logout 1.0): a relying
 * party sends the user's browser here to end the user's session at this server, and optionally
 * to be sent back to it afterwards.
 *
 * <p>The request is validated in full before anything changes. A refused request ends nothing
 * and is never redirected, so a caller cannot use the endpoint as an open redirect, and cannot
 * end someone else's session by presenting an ID token issued for another user.
 */
public interface EndSessionUseCase {

    /**
     * Validates the request and, if it is accepted, ends the session the browser presented and
     * revokes the client's refresh-token families for the user.
     *
     * @param command the parsed request (never {@code null})
     * @return a {@link Uni} emitting the outcome (never {@code null})
     */
    Uni<EndSessionOutcome> endSession(EndSessionCommand command);

    /**
     * A parsed end-session request.
     *
     * @param realm                 the caller's realm (never {@code null})
     * @param idTokenHint           the {@code id_token_hint} parameter, or {@code null}
     * @param clientId              the {@code client_id} parameter, or {@code null}
     * @param postLogoutRedirectUri the {@code post_logout_redirect_uri} parameter, or {@code null}
     * @param state                 the {@code state} parameter, or {@code null}
     * @param sessionId             the session the browser presented, or {@code null} when it
     *                              presented none (or a malformed one)
     */
    record EndSessionCommand(
            RealmKey realm,
            String idTokenHint,
            String clientId,
            String postLogoutRedirectUri,
            String state,
            SessionId sessionId) {

        public EndSessionCommand {
            if (realm == null) {
                throw new IllegalArgumentException("EndSessionCommand realm must not be null");
            }
        }
    }

    /** The outcome of an end-session request. */
    sealed interface EndSessionOutcome {

        /**
         * The session ended; send the browser to {@code location}, a registered post-logout
         * redirect URI with {@code state} appended when one was sent.
         *
         * @param location the exact redirect target (never {@code null})
         */
        record Redirect(String location) implements EndSessionOutcome {
        }

        /** The session ended and no redirect was asked for. */
        record SignedOut() implements EndSessionOutcome {
        }

        /**
         * The request was refused; nothing was ended and the browser must not be redirected.
         *
         * @param description why, for the {@code error_description} (never {@code null})
         */
        record Refused(String description) implements EndSessionOutcome {
        }
    }
}
