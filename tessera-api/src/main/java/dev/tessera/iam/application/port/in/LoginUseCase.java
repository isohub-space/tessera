package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Inbound port for the login endpoint: verifies an end user's presented username/password
 * against the credentials modelled in {@code tessera-domain} and, on success, establishes a
 * new session.
 *
 * <p>This is the seam {@code AuthorizeUseCase} javadoc names as missing: {@code /authorize}
 * still reads the authenticated subject from {@code X-Subject-Id}; this use case is what a
 * login adapter calls to <em>establish</em> the session that a cookie-to-header filter later
 * translates into that header. {@code AuthorizeUseCase} itself is untouched.
 *
 * <p>Only the {@code PasswordHash} credential kind is wired to this first cut — see
 * {@link dev.tessera.iam.domain.credential.Credential} for the full sealed set. WebAuthn,
 * TOTP and recovery-code verification are follow-on work (each is a second factor / second
 * verification path layered onto an already-authenticated session, not a blocker to a first
 * working login), tracked as a deliberate scope cut rather than an oversight.
 */
public interface LoginUseCase {

    /**
     * Verifies {@code username}/{@code password} within {@code realm} and, on success,
     * establishes a new session.
     *
     * @param realm    the realm to authenticate within (never {@code null})
     * @param username the presented login identifier (never {@code null} or blank)
     * @param password the presented plaintext password (never {@code null} or empty; never
     *                 logged or stored — verification happens behind
     *                 {@code PasswordCredentialVerifierPort})
     * @return a {@link Uni} emitting the {@link LoginResult}
     */
    Uni<LoginResult> login(RealmKey realm, String username, String password);

    /**
     * The outcome of a login attempt: a sealed pair of success (a fresh session) or failure.
     * Failure carries no detail beyond a fixed, non-oracle reason code — "unknown username"
     * and "wrong password" render identically to the caller (RFC 9700 §2.2's credential
     * enumeration guidance).
     */
    sealed interface LoginResult permits LoginResult.Authenticated, LoginResult.Denied {

        /**
         * Success: a new session was established for {@code subjectId}.
         *
         * @param sessionId the newly established session's identity (never {@code null})
         * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
         */
        record Authenticated(SessionId sessionId, String subjectId) implements LoginResult {
            public Authenticated {
                if (sessionId == null) {
                    throw new IllegalArgumentException("Authenticated sessionId must not be null");
                }
                if (subjectId == null || subjectId.isBlank()) {
                    throw new IllegalArgumentException("Authenticated subjectId must not be blank");
                }
            }
        }

        /**
         * Failure: the credential did not verify. {@code reason} is a fixed, low-cardinality
         * code (e.g. {@code "invalid_credentials"}) — never anything that would let a caller
         * distinguish "no such user" from "wrong password".
         *
         * @param reason a fixed, non-sensitive reason code (never {@code null} or blank)
         */
        record Denied(String reason) implements LoginResult {
            public Denied {
                if (reason == null || reason.isBlank()) {
                    throw new IllegalArgumentException("Denied reason must not be blank");
                }
            }
        }
    }
}
