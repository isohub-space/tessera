package dev.tessera.statemachine;

import dev.tessera.statemachine.DefaultTypedStateMachine.Handler;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;

/**
 * Fluent builder for {@link TypedStateMachine} instances over a {@code sealed} state type.
 *
 * <p>Typical usage — a sealed {@code AuthStep} permitting record variants:</p>
 * <pre>{@code
 * TypedStateMachine<AuthStep, AuthEvent, AuthOutcome> machine =
 *     TypedStateMachineBuilder.<AuthStep, AuthEvent, AuthOutcome>create(AuthStep.class)
 *         .on(Identify.class,  (s, e) -> Reduction.of(new VerifyPassword(s.user()), null))
 *         .on(VerifyPassword.class, (s, e) -> ...)
 *         .terminal(Authenticated.class, Denied.class)
 *         .buildStrict();   // fails if any permitted variant is unhandled
 * }</pre>
 *
 * <p>Each {@code on(...)} registers exactly one handler per variant {@link Class}; the
 * handler receives the state already narrowed to that variant. {@link #buildStrict()}
 * verifies the registry covers every permitted sealed variant (handled or terminal).</p>
 *
 * <p>The builder is <em>not</em> reusable: call a build method once.</p>
 *
 * @param <S> sealed state type
 * @param <E> event type
 * @param <O> output type
 */
public final class TypedStateMachineBuilder<S, E, O> {

    private final Class<S> stateType;
    private final Map<Class<? extends S>, Handler<S, E, O>> handlers = new LinkedHashMap<>();
    private final Set<Class<? extends S>> terminals = new LinkedHashSet<>();

    private TypedStateMachineBuilder(Class<S> stateType) {
        this.stateType = Objects.requireNonNull(stateType, "stateType must not be null");
    }

    /**
     * Entry point — a fresh builder for the given sealed state type.
     *
     * @param stateType the sealed state interface/class (its permitted subclasses drive
     *                  the completeness diagnostic)
     */
    public static <S, E, O> TypedStateMachineBuilder<S, E, O> create(Class<S> stateType) {
        return new TypedStateMachineBuilder<>(stateType);
    }

    /**
     * Registers the reducer for {@code variant}. The reducer is invoked with the state
     * narrowed to {@code V} and the triggering event, and returns the {@link Reduction}.
     *
     * @throws IllegalStateException if a handler or terminal already exists for the variant
     */
    public <V extends S> TypedStateMachineBuilder<S, E, O> on(
            Class<V> variant, BiFunction<? super V, ? super E, Reduction<S, O>> reducer) {
        return register(variant, null, reducer);
    }

    /**
     * Registers a guarded reducer for {@code variant}: if {@code guard} rejects
     * {@code (state, event)} at {@link TypedStateMachine#step}, a
     * {@link GuardRejectedException} is thrown and the reducer is not invoked.
     *
     * @throws IllegalStateException if a handler or terminal already exists for the variant
     */
    public <V extends S> TypedStateMachineBuilder<S, E, O> on(
            Class<V> variant,
            BiPredicate<? super V, ? super E> guard,
            BiFunction<? super V, ? super E, Reduction<S, O>> reducer) {
        Objects.requireNonNull(guard, "guard must not be null");
        return register(variant, guard, reducer);
    }

    /**
     * Marks one or more variants as terminal — they carry no outgoing transition, and
     * {@link TypedStateMachine#step} on them throws {@link IllegalTransitionException}.
     * Terminal variants count as "covered" for the completeness diagnostic.
     *
     * @throws IllegalStateException if a variant already has a handler
     */
    @SafeVarargs
    public final TypedStateMachineBuilder<S, E, O> terminal(Class<? extends S>... variants) {
        for (Class<? extends S> variant : variants) {
            Objects.requireNonNull(variant, "terminal variant must not be null");
            if (handlers.containsKey(variant)) {
                throw new IllegalStateException(
                        "Variant already has a handler, cannot also be terminal: " + variant);
            }
            terminals.add(variant);
        }
        return this;
    }

    private <V extends S> TypedStateMachineBuilder<S, E, O> register(
            Class<V> variant,
            BiPredicate<? super V, ? super E> guard,
            BiFunction<? super V, ? super E, Reduction<S, O>> reducer) {
        Objects.requireNonNull(variant, "variant must not be null");
        Objects.requireNonNull(reducer, "reducer must not be null");
        if (handlers.containsKey(variant)) {
            throw new IllegalStateException("Duplicate handler for variant: " + variant);
        }
        if (terminals.contains(variant)) {
            throw new IllegalStateException(
                    "Variant already declared terminal, cannot also handle: " + variant);
        }
        // Safe: the handler is only ever invoked with a state whose class is `variant`.
        @SuppressWarnings("unchecked")
        BiFunction<S, E, Reduction<S, O>> widenedReducer =
                (BiFunction<S, E, Reduction<S, O>>) reducer;
        @SuppressWarnings("unchecked")
        BiPredicate<S, E> widenedGuard = (BiPredicate<S, E>) guard;
        handlers.put(variant, new Handler<>(widenedGuard, widenedReducer));
        return this;
    }

    /**
     * Builds the machine without enforcing completeness. Use
     * {@link TypedStateMachine#uncoveredVariants()} to inspect any gaps.
     *
     * @throws IllegalArgumentException if no handler has been registered
     */
    public TypedStateMachine<S, E, O> build() {
        if (handlers.isEmpty()) {
            throw new IllegalArgumentException(
                    "TypedStateMachine must have at least one handler.");
        }
        return new DefaultTypedStateMachine<>(stateType, handlers, terminals);
    }

    /**
     * Builds the machine and asserts that every permitted variant of the sealed state
     * type is accounted for (handled or terminal).
     *
     * @throws IllegalStateException if any permitted variant is uncovered
     * @throws IllegalArgumentException if no handler has been registered
     */
    public TypedStateMachine<S, E, O> buildStrict() {
        TypedStateMachine<S, E, O> machine = build();
        Set<Class<? extends S>> uncovered = machine.uncoveredVariants();
        if (!uncovered.isEmpty()) {
            throw new IllegalStateException(
                    "Sealed state type " + stateType.getName()
                            + " has uncovered variants (no handler or terminal): " + uncovered);
        }
        return machine;
    }
}
