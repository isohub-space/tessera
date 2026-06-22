package dev.tessera.iam.domain.authflow;

import dev.tessera.statemachine.Reduction;
import dev.tessera.statemachine.TypedStateMachine;
import dev.tessera.statemachine.TypedStateMachineBuilder;
import dev.tessera.iam.domain.authflow.AuthEvent.ConsentDenied;
import dev.tessera.iam.domain.authflow.AuthEvent.ConsentGranted;
import dev.tessera.iam.domain.authflow.AuthEvent.IdentifierSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.MfaSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.PasswordSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.StepCancelled;
import dev.tessera.iam.domain.authflow.AuthEvent.WebAuthnAssertionSubmitted;
import dev.tessera.iam.domain.authflow.AuthStep.ConditionalStep;
import dev.tessera.iam.domain.authflow.AuthStep.ConsentGate;
import dev.tessera.iam.domain.authflow.AuthStep.IdentifyUser;
import dev.tessera.iam.domain.authflow.AuthStep.RequireMfa;
import dev.tessera.iam.domain.authflow.AuthStep.StepUp;
import dev.tessera.iam.domain.authflow.AuthStep.VerifyPassword;
import dev.tessera.iam.domain.authflow.AuthStep.WebAuthnAssertion;
import java.util.List;

/**
 * The pure functional core of the authentication flow.
 *
 * <p>{@link #reduce(AuthExchange, AuthEvent)} is a <strong>total, deterministic
 * function</strong> from a state snapshot and one input event to the next snapshot,
 * an {@link AuthOutcome}, and a list of {@link SideEffectRequest}s for the shell to
 * execute. It performs <em>no I/O</em>, reads <em>no clock and no randomness</em>,
 * and never mutates its inputs — anything time- or nonce-dependent is threaded in on
 * the {@link AuthEvent}. Calling {@code reduce} twice on the same inputs yields equal
 * results.
 *
 * <p>This is the design's replacement for Keycloak's authenticator-chain SPI: the
 * flow is data ({@link AuthStep}s in the {@link AuthExchange}), and the engine routes
 * each step through a variant-keyed dispatch table whose completeness over the sealed
 * {@link AuthStep} family is verified when the reducer is built. {@link AuthOutcome.Challenge}
 * is a <em>returned value</em>, never a thrown exception — a missing factor, consent, or
 * step-up pauses the flow cleanly.
 *
 * <p>The reducer is stateless and side-effect-free, so a single instance is safe to
 * share across threads / reactive contexts.
 */
public final class AuthFlowReducer {

    /** Fact key recording how many password attempts have failed on this exchange. */
    static final String FACT_PASSWORD_FAILURES = "auth.password.failures";

    /** Bundles the immutable exchange and the triggering event for a single dispatch. */
    private record Dispatch(AuthExchange state, AuthEvent event) {
    }

    /**
     * Variant-keyed dispatch table over the sealed {@link AuthStep} family, built once
     * per reducer. {@code buildStrict()} verifies every permitted step variant has a
     * handler, so an unhandled step fails fast at construction — the build-time analog
     * of an exhaustive {@code switch}. The engine reads the full {@link ReduceResult}
     * from each transition's output; the reduction's next-state slot mirrors the next
     * step to present.
     */
    private final TypedStateMachine<AuthStep, Dispatch, ReduceResult> dispatcher = buildDispatcher();

    /**
     * The triple produced by a single {@link #reduce} step.
     *
     * @param nextState the new immutable exchange snapshot (never {@code null})
     * @param outcome   the outcome of folding the event (never {@code null})
     * @param effects   the side-effects the shell must execute, in order; defensively
     *                  copied and unmodifiable (never {@code null})
     */
    public record ReduceResult(AuthExchange nextState, AuthOutcome outcome, List<SideEffectRequest> effects) {
        public ReduceResult {
            if (nextState == null) {
                throw new IllegalArgumentException("ReduceResult nextState must not be null");
            }
            if (outcome == null) {
                throw new IllegalArgumentException("ReduceResult outcome must not be null");
            }
            if (effects == null) {
                throw new IllegalArgumentException("ReduceResult effects must not be null");
            }
            effects = List.copyOf(effects);
        }
    }

    /**
     * Folds one event into the exchange, advancing the flow.
     *
     * @param state the current immutable exchange (never {@code null})
     * @param event the input driving the fold (never {@code null})
     * @return the next state, the outcome, and any requested side-effects
     */
    public ReduceResult reduce(AuthExchange state, AuthEvent event) {
        if (state == null) {
            throw new IllegalArgumentException("reduce state must not be null");
        }
        if (event == null) {
            throw new IllegalArgumentException("reduce event must not be null");
        }

        // A terminal exchange ignores further events — idempotent, no effects.
        if (state.status() == AuthExchange.Status.AUTHENTICATED) {
            return new ReduceResult(state, new AuthOutcome.Authenticated(requireSubject(state)), List.of());
        }
        if (state.status() == AuthExchange.Status.DENIED) {
            return new ReduceResult(state, new AuthOutcome.Denied("flow already denied"), List.of());
        }

        // A cancellation denies any non-terminal flow, regardless of the current step.
        if (event instanceof StepCancelled cancelled) {
            return deny(state, "step cancelled by user", cancelled.occurredAtEpochMilli());
        }

        AuthStep current = state.currentStep()
                .orElseThrow(() -> new IllegalStateException("reduce on an exchange with no current step"));

        // Resolve conditional steps to the wrapped step (or skip) before dispatch.
        ResolvedStep resolved = resolve(current, state);
        if (resolved.skipped()) {
            // The condition does not hold: drop the conditional step and re-run the
            // same event against the now-current step.
            return reduce(state.advance(), event);
        }

        return dispatch(resolved.step(), state, event);
    }

    /**
     * Dispatches the event against the (already condition-resolved) current step via the
     * variant-keyed {@link #dispatcher}, which is complete over {@link AuthStep} by
     * construction (see the {@link #dispatcher} field).
     */
    private ReduceResult dispatch(AuthStep step, AuthExchange state, AuthEvent event) {
        return dispatcher.step(step, new Dispatch(state, event)).output();
    }

    /**
     * Assembles the dispatch table — one handler per {@link AuthStep} variant. A bare
     * {@link ConditionalStep} is always unwrapped by {@link #resolve} before dispatch, so
     * reaching it here means the flow was built wrong: it throws, exactly as before.
     * {@code buildStrict()} fails the build if any permitted variant is left unhandled.
     */
    private TypedStateMachine<AuthStep, Dispatch, ReduceResult> buildDispatcher() {
        return TypedStateMachineBuilder.<AuthStep, Dispatch, ReduceResult>create(AuthStep.class)
                .on(IdentifyUser.class,
                        (step, ctx) -> reduction(step, onIdentify(ctx.state(), ctx.event())))
                .on(VerifyPassword.class,
                        (step, ctx) -> reduction(step, onPassword(step, ctx.state(), ctx.event())))
                .on(RequireMfa.class,
                        (step, ctx) -> reduction(step, onMfa(step, ctx.state(), ctx.event())))
                .on(WebAuthnAssertion.class,
                        (step, ctx) -> reduction(step, onWebAuthn(ctx.state(), ctx.event())))
                .on(ConsentGate.class,
                        (step, ctx) -> reduction(step, onConsent(step, ctx.state(), ctx.event())))
                .on(StepUp.class,
                        (step, ctx) -> reduction(step, onStepUp(step, ctx.state(), ctx.event())))
                .on(ConditionalStep.class, (step, ctx) -> {
                    throw new IllegalStateException("ConditionalStep must be resolved before dispatch");
                })
                .buildStrict();
    }

    /**
     * Wraps a {@link ReduceResult} as the dispatch table's {@link Reduction}: the engine
     * reads the result from {@link Reduction#output()}, while the next-state slot mirrors
     * the next step to present (or the dispatched step once the flow has completed).
     */
    private static Reduction<AuthStep, ReduceResult> reduction(AuthStep step, ReduceResult result) {
        return Reduction.of(result.nextState().currentStep().orElse(step), result);
    }

    private ReduceResult onIdentify(AuthExchange state, AuthEvent event) {
        if (event instanceof IdentifierSubmitted submitted) {
            if (submitted.subject() == null) {
                return deny(state, "unknown identifier", submitted.occurredAtEpochMilli());
            }
            AuthExchange next = state.withSubject(submitted.subject()).advance();
            return advanceOrComplete(next, submitted.occurredAtEpochMilli());
        }
        return ignoreUnexpected(state, event);
    }

    private ReduceResult onPassword(VerifyPassword step, AuthExchange state, AuthEvent event) {
        if (event instanceof PasswordSubmitted submitted) {
            if (submitted.correct()) {
                AuthExchange next = state.withFact(FACT_PASSWORD_FAILURES, "0").advance();
                return advanceOrComplete(next, submitted.occurredAtEpochMilli());
            }
            int failures = currentPasswordFailures(state) + 1;
            AuthExchange counted = state.withFact(FACT_PASSWORD_FAILURES, Integer.toString(failures));
            // A failed attempt always bumps the brute-force counter in the shell.
            SideEffectRequest bruteForce = bruteForceEffect(state);
            if (failures >= step.maxAttempts()) {
                AuthExchange denied = counted.denied();
                return new ReduceResult(
                        denied,
                        new AuthOutcome.Denied("password attempts exhausted"),
                        List.of(bruteForce, auditDenied(state, "password attempts exhausted",
                                submitted.occurredAtEpochMilli())));
            }
            // Attempts remain: re-challenge the password step rather than deny.
            AuthExchange challenged = counted.challenged();
            return new ReduceResult(
                    challenged,
                    new AuthOutcome.Challenge(step, new ChallengeDescriptor(
                            ChallengeDescriptor.Kind.STEP_UP_REQUIRED, "password retry")),
                    List.of(bruteForce));
        }
        return ignoreUnexpected(state, event);
    }

    private ReduceResult onMfa(RequireMfa step, AuthExchange state, AuthEvent event) {
        if (event instanceof MfaSubmitted submitted) {
            if (submitted.kind() != step.kind()) {
                return new ReduceResult(
                        state.challenged(),
                        new AuthOutcome.Challenge(step, ChallengeDescriptor.mfa(step.kind())),
                        List.of());
            }
            if (submitted.correct()) {
                AuthExchange next = state.withFact("auth.mfa." + step.kind().name(), "satisfied").advance();
                return advanceOrComplete(next, submitted.occurredAtEpochMilli());
            }
            return new ReduceResult(
                    state.challenged(),
                    new AuthOutcome.Challenge(step, ChallengeDescriptor.mfa(step.kind())),
                    List.of(bruteForceEffect(state)));
        }
        // No MFA answer yet: this is the canonical "Challenge as a value" path.
        return new ReduceResult(
                state.challenged(),
                new AuthOutcome.Challenge(step, ChallengeDescriptor.mfa(step.kind())),
                List.of());
    }

    private ReduceResult onWebAuthn(AuthExchange state, AuthEvent event) {
        AuthStep step = state.currentStep().orElseThrow();
        if (event instanceof WebAuthnAssertionSubmitted submitted) {
            if (submitted.verified()) {
                // Completing WebAuthn is what lets a session truthfully assert
                // phishing-resistant acr.
                AuthExchange next = state.withFact("auth.acr", "phishing-resistant").advance();
                return advanceOrComplete(next, submitted.occurredAtEpochMilli());
            }
            return new ReduceResult(
                    state.challenged(),
                    new AuthOutcome.Challenge(step, ChallengeDescriptor.webAuthn()),
                    List.of(bruteForceEffect(state)));
        }
        return new ReduceResult(
                state.challenged(),
                new AuthOutcome.Challenge(step, ChallengeDescriptor.webAuthn()),
                List.of());
    }

    private ReduceResult onConsent(ConsentGate step, AuthExchange state, AuthEvent event) {
        if (event instanceof ConsentGranted granted && granted.scope().equals(step.scope())) {
            AuthExchange next = state.withFact("auth.consent." + step.scope(), "granted").advance();
            return advanceOrComplete(next, granted.occurredAtEpochMilli());
        }
        if (event instanceof ConsentDenied denied && denied.scope().equals(step.scope())) {
            return deny(state, "consent refused for scope " + step.scope(), denied.occurredAtEpochMilli());
        }
        // No consent decision yet: challenge for it.
        return new ReduceResult(
                state.challenged(),
                new AuthOutcome.Challenge(step, ChallengeDescriptor.consent(step.scope())),
                List.of());
    }

    private ReduceResult onStepUp(StepUp step, AuthExchange state, AuthEvent event) {
        // Step-up is satisfied by a fresh verified factor (password or WebAuthn).
        if (event instanceof PasswordSubmitted submitted && submitted.correct()) {
            AuthExchange next = state.withFact("auth.stepup", "satisfied").advance();
            return advanceOrComplete(next, submitted.occurredAtEpochMilli());
        }
        if (event instanceof WebAuthnAssertionSubmitted submitted && submitted.verified()) {
            AuthExchange next = state.withFact("auth.stepup", "satisfied").advance();
            return advanceOrComplete(next, submitted.occurredAtEpochMilli());
        }
        return new ReduceResult(
                state.challenged(),
                new AuthOutcome.Challenge(step, ChallengeDescriptor.stepUp(step.reason())),
                List.of());
    }

    /**
     * After a step advances, either complete the flow (no steps remain) or emit a
     * {@link AuthOutcome.Continue} for the next step.
     */
    private ReduceResult advanceOrComplete(AuthExchange advanced, long atEpochMilli) {
        if (advanced.isComplete()) {
            Subject subject = requireSubject(advanced);
            AuthExchange authenticated = advanced.authenticated();
            return new ReduceResult(
                    authenticated,
                    new AuthOutcome.Authenticated(subject),
                    List.of(
                            new SideEffectRequest.PersistSession(advanced.realm(), subject, atEpochMilli),
                            new SideEffectRequest.RecordAuditEvent(
                                    advanced.realm(), "AUTH_SUCCESS", subject.subjectId(), atEpochMilli)));
        }
        AuthStep next = advanced.currentStep().orElseThrow();
        return new ReduceResult(advanced, new AuthOutcome.Continue(next), List.of());
    }

    /** Builds a denial result with an audit effect. */
    private ReduceResult deny(AuthExchange state, String reason, long atEpochMilli) {
        return new ReduceResult(
                state.denied(),
                new AuthOutcome.Denied(reason),
                List.of(auditDenied(state, reason, atEpochMilli)));
    }

    /**
     * An unexpected event for the current step is treated as a no-op re-presentation
     * of the same step (deterministic, no effects). Kept as a single helper so the
     * per-step handlers stay focused on their happy/explicit paths.
     */
    private ReduceResult ignoreUnexpected(AuthExchange state, AuthEvent event) {
        AuthStep current = state.currentStep().orElseThrow();
        return new ReduceResult(state, new AuthOutcome.Continue(current), List.of());
    }

    private SideEffectRequest auditDenied(AuthExchange state, String reason, long atEpochMilli) {
        return new SideEffectRequest.RecordAuditEvent(state.realm(), "AUTH_DENIED", reason, atEpochMilli);
    }

    private SideEffectRequest bruteForceEffect(AuthExchange state) {
        Subject subject = state.subject()
                .orElseThrow(() -> new IllegalStateException("brute-force effect needs a resolved subject"));
        return new SideEffectRequest.IncrementBruteForceCounter(state.realm(), subject);
    }

    private int currentPasswordFailures(AuthExchange state) {
        return state.fact(FACT_PASSWORD_FAILURES).map(Integer::parseInt).orElse(0);
    }

    private Subject requireSubject(AuthExchange state) {
        return state.subject()
                .orElseThrow(() -> new IllegalStateException("authenticated exchange without a subject"));
    }

    /**
     * Resolves a possibly-conditional step into the concrete step to dispatch, or a
     * skip signal when the condition does not hold. Pure: the condition is a fact
     * lookup on the exchange, not a predicate evaluation.
     */
    private ResolvedStep resolve(AuthStep step, AuthExchange state) {
        if (step instanceof ConditionalStep conditional) {
            boolean applies = state.fact(conditional.requiredFactKey()).isPresent();
            return applies ? new ResolvedStep(conditional.step(), false) : new ResolvedStep(step, true);
        }
        return new ResolvedStep(step, false);
    }

    /** Internal result of {@link #resolve}: the step to run, and whether to skip it. */
    private record ResolvedStep(AuthStep step, boolean skipped) {
    }
}
