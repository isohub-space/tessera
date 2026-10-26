// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Duration;

/**
 * Inbound port for tessera's hosted sign-in page: the step between an authorization request
 * that arrives with no signed-in user and the code it is answered with.
 *
 * <p>The flow has three steps, one per method:
 * <ol>
 *   <li>{@link #begin}: {@code /authorize} hands over a request with no subject. The client and
 *       redirect URI are validated first, so the sign-in page is never shown for a request
 *       that could not be answered, and the request is parked under a transaction id.</li>
 *   <li>{@link #show}: the sign-in page reads the parked request to render its form.</li>
 *   <li>{@link #submit}: the form is posted. Once the browser binding, the synchronizer token
 *       and the credential all verify, the parked request is consumed and answered with a
 *       code, exactly as {@link AuthorizeUseCase} answers one that arrived signed in.</li>
 * </ol>
 *
 * <p>The browser binding is a secret the adapter keeps in a cookie on the browser that started
 * the flow. A transaction id alone, copied into another browser, is worth nothing.
 */
public interface SignInUseCase {

    /**
     * Validates an authorization request that carries no subject and parks it for sign-in.
     *
     * @param request the structurally valid authorization request (never {@code null})
     * @return {@link BeginResult.Started} with the secrets the browser needs, or
     *         {@link BeginResult.Refused} when the client or redirect URI does not validate
     */
    Uni<BeginResult> begin(AuthorizationRequest request);

    /**
     * Reads a parked request for the sign-in form.
     *
     * @param realm         the realm of the request
     * @param transactionId the transaction id from the sign-in URL (may be {@code null})
     * @param binding       the browser-binding secret from the cookie (may be {@code null})
     * @return the {@link Form} to render, or {@link FormResult.Unavailable} when the transaction
     *         is unknown, expired or bound to another browser
     */
    Uni<FormResult> show(RealmKey realm, String transactionId, String binding);

    /**
     * Verifies a posted sign-in form and, on success, answers the parked request.
     *
     * @param submission the posted values (never {@code null}; its fields may be {@code null})
     * @return the outcome
     */
    Uni<SubmitResult> submit(Submission submission);

    /**
     * What the sign-in form needs: where it posts its transaction and token, and the redirect
     * URI the browser will be sent to once it succeeds (the page's policy must allow it).
     *
     * @param transactionId the transaction id
     * @param csrfToken     the synchronizer token the form carries
     * @param redirectUri   the client's validated redirect URI
     */
    record Form(String transactionId, String csrfToken, String redirectUri) {
    }

    /**
     * A posted sign-in form, as the browser sent it.
     *
     * @param realm         the realm of the request
     * @param transactionId the posted transaction id
     * @param binding       the browser-binding secret from the cookie
     * @param csrfToken     the posted synchronizer token
     * @param username      the posted username
     * @param password      the posted password
     */
    record Submission(
            RealmKey realm,
            String transactionId,
            String binding,
            String csrfToken,
            String username,
            String password) {

        @Override
        public String toString() {
            // Never render the password, should a submission ever reach a log line.
            return "Submission[realm=" + realm + ", transactionId=" + transactionId + "]";
        }
    }

    /** The outcome of {@link #begin}. */
    sealed interface BeginResult permits BeginResult.Started, BeginResult.Refused {

        /**
         * The request is parked: send the browser to the sign-in page with
         * {@code transactionId}, and give it {@code binding} in a cookie that lives as long as
         * the transaction.
         *
         * @param transactionId the transaction id for the sign-in URL
         * @param binding       the browser-binding secret, for the cookie only
         * @param lifetime      how long the transaction stays usable
         */
        record Started(String transactionId, String binding, Duration lifetime) implements BeginResult {
        }

        /**
         * The request cannot be answered: an unknown client, a client not allowed the code
         * grant, or an unregistered redirect URI. Never redirected.
         *
         * @param error       the OAuth error
         * @param description a non-sensitive description
         */
        record Refused(AuthorizationError error, String description) implements BeginResult {
        }
    }

    /** The outcome of {@link #show}. */
    sealed interface FormResult permits FormResult.Shown, FormResult.Unavailable {

        /** @param form the form to render */
        record Shown(Form form) implements FormResult {
        }

        /** Unknown, expired or bound to another browser; the user starts again at the client. */
        record Unavailable() implements FormResult {
        }
    }

    /** The outcome of {@link #submit}. */
    sealed interface SubmitResult
            permits SubmitResult.Completed, SubmitResult.Denied, SubmitResult.Unavailable,
                    SubmitResult.Refused {

        /**
         * Signed in and answered: redirect to {@code redirectUri} with {@code code} and
         * {@code state}. The sign-in also established {@code sessionId}.
         *
         * @param redirectUri the client's validated redirect URI
         * @param code        the issued authorization code
         * @param state       the client's {@code state}
         * @param sessionId   the session the sign-in established
         */
        record Completed(String redirectUri, String code, String state, SessionId sessionId)
                implements SubmitResult {
        }

        /**
         * The credential did not verify. The transaction stays usable, so the form is shown
         * again. Unknown username and wrong password are not told apart.
         *
         * @param form the form to render again
         */
        record Denied(Form form) implements SubmitResult {
        }

        /**
         * The transaction is unknown, expired, already used, bound to another browser, or the
         * synchronizer token does not match. No credential was checked.
         */
        record Unavailable() implements SubmitResult {
        }

        /**
         * The user signed in, but the request could no longer be answered (the client changed
         * meanwhile). Never redirected.
         *
         * @param error       the OAuth error
         * @param description a non-sensitive description
         */
        record Refused(AuthorizationError error, String description) implements SubmitResult {
        }
    }
}
