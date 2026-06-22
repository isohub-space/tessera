package dev.tessera.iam.domain.authflow;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An immutable snapshot of an in-progress authentication flow, threaded through the
 * {@link AuthFlowReducer} by the shell.
 *
 * <p>This is the "state" half of the fold {@code (AuthExchange, AuthEvent) ->
 * (AuthExchange', outcome, effects)}. It is <strong>fully immutable</strong>: every
 * collection is defensively copied and exposed unmodifiable, and every transition
 * helper ({@code with...} / {@code advance} / {@code complete} / {@code deny})
 * returns a <em>new</em> instance. Nothing here is ever mutated in place, so a
 * caller can keep prior snapshots for audit/replay and the reducer can be invoked
 * twice on the same input without observable difference.
 *
 * @param realm           the realm (tenant key) the flow runs within (never {@code null})
 * @param remainingSteps  the ordered steps still to satisfy; the head is the current
 *                        step (never {@code null}; copied unmodifiable)
 * @param completedSteps  the steps already satisfied, in completion order (never
 *                        {@code null}; copied unmodifiable)
 * @param subject         the identified principal once {@link AuthStep.IdentifyUser}
 *                        completes, otherwise empty
 * @param facts           accumulated audit-friendly facts (satisfied factors,
 *                        consent state, failure counters), keyed by stable string
 *                        (never {@code null}; copied unmodifiable)
 * @param status          the coarse lifecycle status, for audit and shell routing
 *                        (never {@code null})
 */
public record AuthExchange(
        RealmKey realm,
        List<AuthStep> remainingSteps,
        List<AuthStep> completedSteps,
        Optional<Subject> subject,
        Map<String, String> facts,
        Status status) {

    /** Coarse lifecycle status of an exchange, for audit and shell routing. */
    public enum Status {
        /** The flow is mid-progress, advancing through steps. */
        IN_PROGRESS,
        /** The flow is paused awaiting a client response to a challenge. */
        CHALLENGED,
        /** The flow completed successfully; a subject is authenticated. */
        AUTHENTICATED,
        /** The flow terminated in refusal. */
        DENIED
    }

    public AuthExchange {
        if (realm == null) {
            throw new IllegalArgumentException("AuthExchange realm must not be null");
        }
        if (remainingSteps == null) {
            throw new IllegalArgumentException("AuthExchange remainingSteps must not be null");
        }
        if (completedSteps == null) {
            throw new IllegalArgumentException("AuthExchange completedSteps must not be null");
        }
        if (subject == null) {
            throw new IllegalArgumentException("AuthExchange subject must not be null (use Optional.empty())");
        }
        if (facts == null) {
            throw new IllegalArgumentException("AuthExchange facts must not be null");
        }
        if (status == null) {
            throw new IllegalArgumentException("AuthExchange status must not be null");
        }
        // Defensive, unmodifiable copies keep the snapshot immutable.
        remainingSteps = List.copyOf(remainingSteps);
        completedSteps = List.copyOf(completedSteps);
        facts = Collections.unmodifiableMap(new LinkedHashMap<>(facts));
    }

    /**
     * Starts a fresh exchange for a realm and an ordered list of steps.
     *
     * @param realm the realm scope (never {@code null})
     * @param steps the ordered flow steps (never {@code null}, never empty)
     * @return a new {@link Status#IN_PROGRESS} exchange with no facts and no subject
     */
    public static AuthExchange start(RealmKey realm, List<AuthStep> steps) {
        if (steps == null || steps.isEmpty()) {
            throw new IllegalArgumentException("AuthExchange must start with at least one step");
        }
        return new AuthExchange(
                realm, steps, List.of(), Optional.empty(), Map.of(), Status.IN_PROGRESS);
    }

    /**
     * The step the flow is currently on, i.e. the head of {@link #remainingSteps}.
     *
     * @return the current step, or empty if no steps remain
     */
    public Optional<AuthStep> currentStep() {
        return remainingSteps.isEmpty() ? Optional.empty() : Optional.of(remainingSteps.get(0));
    }

    /** @return {@code true} if no steps remain to satisfy. */
    public boolean isComplete() {
        return remainingSteps.isEmpty();
    }

    /**
     * Looks up an accumulated fact.
     *
     * @param key the fact key
     * @return the fact value if present
     */
    public Optional<String> fact(String key) {
        return Optional.ofNullable(facts.get(key));
    }

    /**
     * Returns a copy with the resolved subject attached.
     *
     * @param resolved the identified principal (never {@code null})
     * @return a new exchange carrying the subject
     */
    public AuthExchange withSubject(Subject resolved) {
        if (resolved == null) {
            throw new IllegalArgumentException("withSubject resolved must not be null");
        }
        return new AuthExchange(
                realm, remainingSteps, completedSteps, Optional.of(resolved), facts, status);
    }

    /**
     * Returns a copy with an extra fact recorded.
     *
     * @param key   the fact key (never {@code null})
     * @param value the fact value (never {@code null})
     * @return a new exchange with the fact added (replacing any prior value)
     */
    public AuthExchange withFact(String key, String value) {
        if (key == null || value == null) {
            throw new IllegalArgumentException("withFact key/value must not be null");
        }
        Map<String, String> next = new LinkedHashMap<>(facts);
        next.put(key, value);
        return new AuthExchange(realm, remainingSteps, completedSteps, subject, next, status);
    }

    /**
     * Returns a copy with the given status.
     *
     * @param newStatus the new status (never {@code null})
     * @return a new exchange with the status replaced
     */
    public AuthExchange withStatus(Status newStatus) {
        if (newStatus == null) {
            throw new IllegalArgumentException("withStatus newStatus must not be null");
        }
        return new AuthExchange(realm, remainingSteps, completedSteps, subject, facts, newStatus);
    }

    /**
     * Advances past the current step: moves the head of {@link #remainingSteps} onto
     * {@link #completedSteps}. The exchange stays {@link Status#IN_PROGRESS}.
     *
     * @return a new exchange with the current step marked complete
     * @throws IllegalStateException if there is no current step to advance past
     */
    public AuthExchange advance() {
        if (remainingSteps.isEmpty()) {
            throw new IllegalStateException("Cannot advance an exchange with no remaining steps");
        }
        List<AuthStep> nextRemaining = new ArrayList<>(remainingSteps);
        AuthStep done = nextRemaining.remove(0);
        List<AuthStep> nextCompleted = new ArrayList<>(completedSteps);
        nextCompleted.add(done);
        return new AuthExchange(
                realm, nextRemaining, nextCompleted, subject, facts, Status.IN_PROGRESS);
    }

    /**
     * Marks the exchange paused awaiting a client response. The remaining steps are
     * left untouched (the head is still the pending step).
     *
     * @return a new {@link Status#CHALLENGED} exchange
     */
    public AuthExchange challenged() {
        return withStatus(Status.CHALLENGED);
    }

    /**
     * Marks the exchange authenticated.
     *
     * @return a new {@link Status#AUTHENTICATED} exchange
     */
    public AuthExchange authenticated() {
        return withStatus(Status.AUTHENTICATED);
    }

    /**
     * Marks the exchange denied.
     *
     * @return a new {@link Status#DENIED} exchange
     */
    public AuthExchange denied() {
        return withStatus(Status.DENIED);
    }
}
