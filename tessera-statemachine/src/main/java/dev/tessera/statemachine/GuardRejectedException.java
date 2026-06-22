package dev.tessera.statemachine;

import java.io.Serial;

/**
 * Thrown by {@link StateMachine#trigger} when a matching transition is found
 * but its {@link Transition#guard()} evaluates to {@code false}.
 */
public final class GuardRejectedException extends RuntimeException {

    @Serial private static final long serialVersionUID = 1L;

    private final transient Object fromState;
    private final transient Object event;
    private final transient Object toState;

    public <S, E> GuardRejectedException(S fromState, E event, S toState) {
        super(String.format(
                "Guard rejected transition from '%s' on event '%s' to '%s'.",
                fromState, event, toState));
        this.fromState = fromState;
        this.event = event;
        this.toState = toState;
    }

    /**
     * For type-routed machines: the variant guard rejected {@code (fromState, event)}
     * before a next state was computed, so {@link #toState()} is {@code null}.
     */
    public <S, E> GuardRejectedException(S fromState, E event) {
        super(String.format(
                "Guard rejected transition from '%s' on event '%s'.", fromState, event));
        this.fromState = fromState;
        this.event = event;
        this.toState = null;
    }

    /** The state the machine was in when the guard was evaluated. */
    public Object fromState() {
        return fromState;
    }

    /** The event that triggered the guard evaluation. */
    public Object event() {
        return event;
    }

    /** The target state that would have been entered if the guard had passed. */
    public Object toState() {
        return toState;
    }
}
