package dev.tessera.statemachine;

import java.io.Serial;
import java.util.Set;

/**
 * Thrown by {@link StateMachine#trigger} when no transition is defined for the
 * current (state, event) pair.
 */
public final class IllegalTransitionException extends RuntimeException {

    @Serial private static final long serialVersionUID = 1L;

    private final transient Object fromState;
    private final transient Object event;
    private final transient Set<?> availableEvents;

    public <S, E> IllegalTransitionException(S fromState, E event, Set<E> availableEvents) {
        super(String.format(
                "No transition defined from state '%s' on event '%s'. Available events: %s",
                fromState, event, availableEvents));
        this.fromState = fromState;
        this.event = event;
        this.availableEvents = Set.copyOf(availableEvents);
    }

    /**
     * For type-routed machines: no handler is registered for the runtime variant of
     * {@code fromState}. {@link #availableEvents()} is empty — events are not enumerated
     * per variant in a typed machine.
     */
    public <S, E> IllegalTransitionException(S fromState, E event) {
        super(String.format(
                "No transition registered for state variant '%s' on event '%s'.",
                fromState == null ? "null" : fromState.getClass().getName(), event));
        this.fromState = fromState;
        this.event = event;
        this.availableEvents = Set.of();
    }

    /** The state the machine was in when the event was fired. */
    public Object fromState() {
        return fromState;
    }

    /** The event that had no matching transition. */
    public Object event() {
        return event;
    }

    /** Events that do have at least one defined transition from {@code fromState}. */
    public Set<?> availableEvents() {
        return availableEvents;
    }
}
