package dev.tessera.statemachine;

import java.util.Objects;

/**
 * The result of a single typed transition: the {@code nextState} the machine moves to,
 * paired with an optional domain {@code output} the transition emits.
 *
 * <p>{@code S} is the (typically {@code sealed}) state type; {@code O} is the output type
 * — for example an outcome, a list of side-effect requests, or any value a reducer wants
 * to surface alongside the new state. {@code output} may be {@code null} when a transition
 * emits nothing.</p>
 *
 * @param nextState the state after the transition (never {@code null})
 * @param output    the value emitted by the transition, or {@code null}
 * @param <S>       state type
 * @param <O>       output type
 */
public record Reduction<S, O>(S nextState, O output) {

    public Reduction {
        Objects.requireNonNull(nextState, "nextState must not be null");
    }

    /**
     * A reduction to {@code nextState} that emits no output.
     */
    public static <S, O> Reduction<S, O> to(S nextState) {
        return new Reduction<>(nextState, null);
    }

    /**
     * A reduction to {@code nextState} that emits {@code output}.
     */
    public static <S, O> Reduction<S, O> of(S nextState, O output) {
        return new Reduction<>(nextState, output);
    }
}
