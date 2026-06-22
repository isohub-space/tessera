package dev.tessera.statemachine;

import java.util.List;
import java.util.Set;

/**
 * Generic, framework-free state machine abstraction.
 *
 * <p>{@code S} is the state type; {@code E} is the event (trigger) type.
 * Implementations are created via {@link StateMachineBuilder} and are
 * <em>not</em> thread-safe by default — wrap in a synchronised or copy-on-write
 * façade if concurrent access is required.</p>
 *
 * @param <S> state type
 * @param <E> event type
 */
public interface StateMachine<S, E> {

    /**
     * Returns the current state of the machine.
     */
    S currentState();

    /**
     * Fires {@code event} from the current state, advancing to the target state.
     *
     * <p>Evaluation order:</p>
     * <ol>
     *   <li>Look up a {@link Transition} whose {@code from} equals the current
     *       state and whose {@code event} equals the supplied event.</li>
     *   <li>If none exists → {@link IllegalTransitionException}.</li>
     *   <li>Evaluate the transition's guard (if any). If it returns
     *       {@code false} → {@link GuardRejectedException}.</li>
     *   <li>Set current state to {@code transition.to()}.</li>
     *   <li>Invoke the {@code onTransit} callback (if any).</li>
     *   <li>Return the new current state.</li>
     * </ol>
     *
     * @param event the event to fire
     * @return the new current state after the transition
     * @throws IllegalTransitionException if no transition is defined for
     *                                    (currentState, event)
     * @throws GuardRejectedException     if the transition exists but its
     *                                    guard returns {@code false}
     */
    S trigger(E event);

    /**
     * Returns {@code true} if firing {@code event} from the current state
     * would succeed — i.e. a transition exists <em>and</em> its guard passes.
     *
     * <p>This is a pure query: it does <em>not</em> change state.</p>
     */
    boolean canTrigger(E event);

    /**
     * Returns the set of events that would succeed from the current state
     * (transition defined <em>and</em> guard passes).
     *
     * <p>An empty set means the machine is effectively stuck (no available move).
     * If the current state is also terminal the machine has reached a valid
     * end; otherwise it is in a dead-end.</p>
     */
    Set<E> enabledEvents();

    /**
     * Returns all states reachable from {@code state} via exactly one
     * transition (guard is <em>not</em> evaluated — only topology matters).
     */
    Set<S> reachableFrom(S state);

    /**
     * Returns {@code true} if {@code state} was declared as a terminal
     * (accepting) state via {@link StateMachineBuilder#terminal}.
     */
    boolean isTerminal(S state);

    /**
     * Convenience — equivalent to {@code isTerminal(currentState())}.
     */
    default boolean isTerminal() {
        return isTerminal(currentState());
    }

    /**
     * Returns all transitions registered in this machine.
     */
    List<Transition<S, E>> transitions();
}
