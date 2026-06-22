package dev.tessera.statemachine;

import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;

/**
 * Immutable description of a single state-machine edge.
 *
 * <p>{@code S} is the state type; {@code E} is the event (trigger) type. Both
 * can be any object — enum constants, strings, or domain value types — so long
 * as they implement {@link Object#equals} and {@link Object#hashCode}
 * correctly.</p>
 *
 * <p>The optional {@code guard} is evaluated just before the transition fires.
 * If it returns {@code false} the transition is skipped and
 * {@link GuardRejectedException} is thrown by the machine.
 * A {@code null} guard is treated as unconditionally {@code true}.</p>
 *
 * <p>The optional {@code onTransit} callback is invoked with {@code (from, to)}
 * after the guard passes and the machine has moved to the target state. It is
 * meant for lightweight side-effects (logging, metrics). It MUST NOT throw; any
 * unchecked exception propagates out of {@link StateMachine#trigger} uncaught.</p>
 *
 * @param <S> state type
 * @param <E> event type
 */
public record Transition<S, E>(
        S from,
        E event,
        S to,
        BooleanSupplier guard,
        BiConsumer<S, S> onTransit
) {

    /**
     * Convenience constructor — no guard, no action.
     */
    public Transition(S from, E event, S to) {
        this(from, event, to, () -> true, (_, _) -> {});
    }

    /**
     * Convenience constructor — guard only, no action.
     */
    public Transition(S from, E event, S to, BooleanSupplier guard) {
        this(from, event, to, guard, (_, _) -> {});
    }

    /**
     * Returns {@code true} if no guard is configured or the guard evaluates to
     * {@code true}.
     */
    public boolean guardPasses() {
        return guard == null || guard.getAsBoolean();
    }

    /**
     * Fires the {@code onTransit} callback if one is set.
     */
    void fireCallback() {
        if (onTransit != null) {
            onTransit.accept(from, to);
        }
    }
}
