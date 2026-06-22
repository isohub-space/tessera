package dev.tessera.iam.domain.authflow;

/**
 * An input that drives the {@link AuthFlowReducer} fold
 *.
 *
 * <p>Each event is the client's answer to the step the flow is currently on. The
 * shell verifies the actual secret (constant-time password compare, WebAuthn
 * signature check, TOTP window) <em>before</em> constructing the event — the domain
 * never sees a raw secret. Instead an event carries only the <strong>verified
 * verdict</strong> (e.g. {@link PasswordSubmitted#correct()}), so the reducer stays
 * a pure decision function over already-checked facts.
 *
 * <p><strong>Purity note (time/nonce).</strong> The reducer takes no clock and no
 * randomness. Anything time- or nonce-dependent (an issued challenge nonce, an
 * occurrence timestamp for audit) is passed <em>in</em> on the event by the shell —
 * see {@link #occurredAtEpochMilli()} — never read from {@code Instant.now()} inside
 * the core. This keeps {@code reduce} deterministic and replayable.
 */
public sealed interface AuthEvent
        permits AuthEvent.IdentifierSubmitted,
                AuthEvent.PasswordSubmitted,
                AuthEvent.MfaSubmitted,
                AuthEvent.WebAuthnAssertionSubmitted,
                AuthEvent.ConsentGranted,
                AuthEvent.ConsentDenied,
                AuthEvent.StepCancelled {

    /**
     * The shell-supplied wall-clock instant this event occurred at, as epoch
     * milliseconds. Injected so the reducer can stamp emitted
     * {@link SideEffectRequest}s (audit, lockout) without reading a clock itself.
     *
     * @return the event time in epoch milliseconds
     */
    long occurredAtEpochMilli();

    /**
     * The user submitted an identifier and the shell resolved it to a subject.
     *
     * @param subject             the resolved principal, or {@code null} if the
     *                            identifier matched no user (handled as a denial)
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record IdentifierSubmitted(Subject subject, long occurredAtEpochMilli) implements AuthEvent {
    }

    /**
     * The user submitted a password and the shell verified it.
     *
     * @param correct             whether the stored verifier accepted the password
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record PasswordSubmitted(boolean correct, long occurredAtEpochMilli) implements AuthEvent {
    }

    /**
     * The user submitted a second factor and the shell verified it.
     *
     * @param kind                the factor family submitted (never {@code null})
     * @param correct             whether the factor verified
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record MfaSubmitted(MfaKind kind, boolean correct, long occurredAtEpochMilli) implements AuthEvent {
        public MfaSubmitted {
            if (kind == null) {
                throw new IllegalArgumentException("MfaSubmitted kind must not be null");
            }
        }
    }

    /**
     * The user submitted a WebAuthn assertion and the shell verified the signature.
     *
     * @param verified            whether the assertion verified against a registered
     *                            authenticator
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record WebAuthnAssertionSubmitted(boolean verified, long occurredAtEpochMilli) implements AuthEvent {
    }

    /**
     * The user granted consent for the pending scope.
     *
     * @param scope               the scope consented to (never {@code null})
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record ConsentGranted(String scope, long occurredAtEpochMilli) implements AuthEvent {
        public ConsentGranted {
            if (scope == null) {
                throw new IllegalArgumentException("ConsentGranted scope must not be null");
            }
        }
    }

    /**
     * The user refused consent for the pending scope.
     *
     * @param scope               the scope refused (never {@code null})
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record ConsentDenied(String scope, long occurredAtEpochMilli) implements AuthEvent {
        public ConsentDenied {
            if (scope == null) {
                throw new IllegalArgumentException("ConsentDenied scope must not be null");
            }
        }
    }

    /**
     * The user abandoned the current step (e.g. cancelled an MFA prompt).
     *
     * @param occurredAtEpochMilli see {@link #occurredAtEpochMilli()}
     */
    record StepCancelled(long occurredAtEpochMilli) implements AuthEvent {
    }
}
