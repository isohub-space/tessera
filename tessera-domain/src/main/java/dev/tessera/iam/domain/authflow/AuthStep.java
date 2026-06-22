package dev.tessera.iam.domain.authflow;

/**
 * One step of an authentication flow, modelled as immutable data
 *.
 *
 * <p>This is the design's replacement for Keycloak's authenticator-chain SPI: where
 * Keycloak wires a graph of {@code Authenticator} provider beans at deploy time,
 * here a flow is simply an ordered, sealed list of {@code AuthStep} <em>values</em>.
 * Each member is a minimal record carrying only the parameters of the step — never
 * behaviour. The {@link AuthFlowReducer} interprets the steps; the steps themselves
 * do nothing.
 *
 * <p>Because the hierarchy is sealed, any exhaustive {@code switch} over an
 * {@code AuthStep} is checked at compile time: adding a new kind of step forces
 * every flow decision to acknowledge it, which is exactly the deploy-time-wiring
 * failure mode this design calls out.
 */
public sealed interface AuthStep
        permits AuthStep.IdentifyUser,
                AuthStep.VerifyPassword,
                AuthStep.RequireMfa,
                AuthStep.WebAuthnAssertion,
                AuthStep.ConsentGate,
                AuthStep.StepUp,
                AuthStep.ConditionalStep {

    /**
     * Resolve the end-user identifier (username / email) into a {@link Subject}.
     * The first step of every interactive flow; carries no parameters of its own.
     */
    record IdentifyUser() implements AuthStep {
    }

    /**
     * Verify a knowledge factor (password) against the stored verifier.
     *
     * @param maxAttempts the number of wrong submissions tolerated before the step
     *                    denies and asks the shell to lock out (brute-force defense,
     *                    threat #12); must be at least one
     */
    record VerifyPassword(int maxAttempts) implements AuthStep {
        public VerifyPassword {
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("VerifyPassword maxAttempts must be >= 1");
            }
        }
    }

    /**
     * Require a second factor of the given {@link MfaKind}. Reaching this step
     * yields a {@link AuthOutcome.Challenge} rather than continuing silently.
     *
     * @param kind the second-factor family demanded (never {@code null})
     */
    record RequireMfa(MfaKind kind) implements AuthStep {
        public RequireMfa {
            if (kind == null) {
                throw new IllegalArgumentException("RequireMfa kind must not be null");
            }
        }
    }

    /**
     * Require a phishing-resistant WebAuthn / passkey assertion. Modelled as its
     * own step (rather than a {@link RequireMfa} of {@link MfaKind#WEBAUTHN}) because
     * it is the assurance-bearing factor: completing it is what lets a session
     * truthfully assert phishing-resistant {@code acr}.
     */
    record WebAuthnAssertion() implements AuthStep {
    }

    /**
     * Gate the flow on the user granting consent for a set of scopes.
     *
     * @param scope the OAuth2 scope string being consented to (never {@code null})
     */
    record ConsentGate(String scope) implements AuthStep {
        public ConsentGate {
            if (scope == null) {
                throw new IllegalArgumentException("ConsentGate scope must not be null");
            }
        }
    }

    /**
     * Demand a fresh re-authentication for a safety-critical / commanding action,
     * even within an otherwise-authenticated session.
     *
     * @param reason an audit-friendly description of why step-up was triggered
     *               (never {@code null})
     */
    record StepUp(String reason) implements AuthStep {
        public StepUp {
            if (reason == null) {
                throw new IllegalArgumentException("StepUp reason must not be null");
            }
        }
    }

    /**
     * A step that only applies when a named condition holds; otherwise the reducer
     * skips it. The condition itself is evaluated as <em>data</em> against facts
     * already in the {@link AuthExchange} — no predicate lambda lives in the domain,
     * keeping the step a pure value.
     *
     * @param requiredFactKey the {@link AuthExchange} fact key that must be present
     *                       for the wrapped step to apply (never {@code null})
     * @param step           the step to run when the condition holds (never
     *                       {@code null}; itself never another {@code ConditionalStep})
     */
    record ConditionalStep(String requiredFactKey, AuthStep step) implements AuthStep {
        public ConditionalStep {
            if (requiredFactKey == null) {
                throw new IllegalArgumentException("ConditionalStep requiredFactKey must not be null");
            }
            if (step == null) {
                throw new IllegalArgumentException("ConditionalStep step must not be null");
            }
            if (step instanceof ConditionalStep) {
                throw new IllegalArgumentException("ConditionalStep must not wrap another ConditionalStep");
            }
        }
    }
}
