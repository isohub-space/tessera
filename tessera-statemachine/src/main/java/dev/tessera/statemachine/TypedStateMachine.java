package dev.tessera.statemachine;

import java.util.Set;

/**
 * A state machine whose states are a {@link Class}-discriminated family — typically a
 * {@code sealed} interface permitting {@code record} variants that carry payload data —
 * complementing the value-keyed {@link StateMachine} / {@link EnumStateMachine}.
 *
 * <p>Where {@link StateMachine} matches a state by <em>value equality</em> and moves to a
 * <em>constant</em> target, a typed machine routes by the state's <em>runtime variant
 * type</em> and computes the next state as a function of {@code (state, event)}. So two
 * values of the same variant that differ only in payload are the <em>same</em> logical
 * state for routing, and a transition is free to build a fresh, payload-carrying next
 * state. Each transition yields a {@link Reduction} pairing that next state with a domain
 * output — which is what lets a reducer (next state + outcome/effects) fit the model.</p>
 *
 * <p>Because the state family is usually {@code sealed}, the complete set of permitted
 * variants is known at build time, so the machine offers {@link #uncoveredVariants()} —
 * the type-level analogue of {@link EnumStateMachine#coverage()} — to detect a variant
 * with no registered handler. A registry is therefore no weaker than an exhaustive
 * {@code switch}: completeness is recovered as a build/test-time check.</p>
 *
 * <p>Instances are immutable and thread-safe: {@link #step} is a pure function of its
 * arguments and holds no current state (the caller owns the state value).</p>
 *
 * @param <S> sealed state type (variants are usually records)
 * @param <E> event type
 * @param <O> transition output type
 */
public interface TypedStateMachine<S, E, O> {

    /**
     * Routes {@code event} through the handler registered for {@code state}'s runtime
     * variant and returns the resulting {@link Reduction}.
     *
     * @param state the current state value (its variant selects the handler)
     * @param event the event to apply
     * @return the next state paired with the transition's output
     * @throws IllegalTransitionException if no handler is registered for the variant
     *                                    (including a variant declared terminal)
     * @throws GuardRejectedException     if the variant's guard rejects {@code (state, event)}
     */
    Reduction<S, O> step(S state, E event);

    /**
     * Whether {@link #step} would succeed for {@code (state, event)} — a pure query that
     * applies the guard but no transition.
     */
    boolean canStep(S state, E event);

    /**
     * Whether {@code state}'s variant was declared terminal (it has no outgoing
     * transition and {@link #step} on it is illegal).
     */
    boolean isTerminal(S state);

    /**
     * The variant types that have a registered handler.
     */
    Set<Class<? extends S>> coveredVariants();

    /**
     * The permitted variants of the sealed state type that have neither a registered
     * handler nor a terminal declaration. Empty means every variant is accounted for.
     *
     * <p>Returns an empty set when the state type is not {@code sealed} — the permitted
     * set is then not known to the runtime and completeness cannot be asserted.</p>
     */
    Set<Class<? extends S>> uncoveredVariants();
}
