package dev.tessera.iam.domain.authflow;

/**
 * The result of folding one {@link AuthEvent} into an {@link AuthExchange}
 *.
 *
 * <p>The cornerstone design choice: <strong>{@link Challenge} is a first-class
 * return value, never an exception side-channel</strong>. A required action,
 * step-up, or pending second factor is a normal {@code AuthOutcome} the shell
 * inspects and reflects back to the client — control flow stays linear and the
 * reducer stays a total function. The four members exhaustively cover the states a
 * flow can be in after a single event:
 *
 * <ul>
 *   <li>{@link Continue} — the step succeeded; advance to the next {@link AuthStep}.</li>
 *   <li>{@link Challenge} — the flow needs something more from the client before it
 *       can continue (MFA prompt, consent, step-up).</li>
 *   <li>{@link Authenticated} — terminal success, carrying the resolved
 *       {@link Subject}.</li>
 *   <li>{@link Denied} — terminal failure, carrying a reason for audit.</li>
 * </ul>
 */
public sealed interface AuthOutcome
        permits AuthOutcome.Continue,
                AuthOutcome.Challenge,
                AuthOutcome.Authenticated,
                AuthOutcome.Denied {

    /**
     * The current step was satisfied and the flow should proceed.
     *
     * @param nextStep the next step the flow will attempt (never {@code null})
     */
    record Continue(AuthStep nextStep) implements AuthOutcome {
        public Continue {
            if (nextStep == null) {
                throw new IllegalArgumentException("Continue nextStep must not be null");
            }
        }
    }

    /**
     * The flow is paused awaiting a client response. This is returned, not thrown.
     *
     * @param pendingStep the step that raised the challenge (never {@code null})
     * @param descriptor  what the client is being asked to do (never {@code null})
     */
    record Challenge(AuthStep pendingStep, ChallengeDescriptor descriptor) implements AuthOutcome {
        public Challenge {
            if (pendingStep == null) {
                throw new IllegalArgumentException("Challenge pendingStep must not be null");
            }
            if (descriptor == null) {
                throw new IllegalArgumentException("Challenge descriptor must not be null");
            }
        }
    }

    /**
     * Terminal success: every step completed and the principal is resolved.
     *
     * @param subject the authenticated principal (never {@code null})
     */
    record Authenticated(Subject subject) implements AuthOutcome {
        public Authenticated {
            if (subject == null) {
                throw new IllegalArgumentException("Authenticated subject must not be null");
            }
        }
    }

    /**
     * Terminal failure, carrying an audit-friendly reason. No exception is raised;
     * the shell records the reason and ends the flow.
     *
     * @param reason why authentication was refused (never {@code null} or blank)
     */
    record Denied(String reason) implements AuthOutcome {
        public Denied {
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("Denied reason must not be null or blank");
            }
        }
    }
}
