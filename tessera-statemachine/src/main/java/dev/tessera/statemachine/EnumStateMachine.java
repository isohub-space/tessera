package dev.tessera.statemachine;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Specialised state machine for {@link Enum}-based states.
 *
 * <p>Wraps a {@link StateMachine} built by {@link StateMachineBuilder} and
 * exposes additional enum-specific diagnostics:</p>
 * <ul>
 *   <li>{@link #unreachableStates()} — enum constants no outgoing transition leads to</li>
 *   <li>{@link #deadEndStates()} — non-terminal states with no outgoing transitions</li>
 *   <li>{@link #coverage()} — fraction of enum values reachable in the topology</li>
 * </ul>
 *
 * <p>Create instances via {@link EnumStateMachine#builder}:</p>
 * <pre>{@code
 * EnumStateMachine<OrderStatus, OrderEvent> machine =
 *     EnumStateMachine.builder(OrderStatus.class)
 *         .<OrderEvent>transition(PLACED,    OrderEvent.PAY,     PAID)
 *         .transition(PAID,      OrderEvent.SHIP,    SHIPPED)
 *         .transition(SHIPPED,   OrderEvent.DELIVER, DELIVERED)
 *         .terminal(DELIVERED, CANCELLED)
 *         .buildEnum(PLACED);
 * }</pre>
 *
 * @param <S> enum state type
 * @param <E> event type (need not be an enum)
 */
public final class EnumStateMachine<S extends Enum<S>, E> implements StateMachine<S, E> {

    private final StateMachine<S, E> delegate;
    private final Class<S> stateClass;
    private final Set<S> allStates;

    private EnumStateMachine(StateMachine<S, E> delegate, Class<S> stateClass) {
        this.delegate = delegate;
        this.stateClass = stateClass;
        this.allStates = EnumSet.allOf(stateClass);
    }

    // -------------------------------------------------------------------------
    // StateMachine delegation
    // -------------------------------------------------------------------------

    @Override
    public S currentState() {
        return delegate.currentState();
    }

    @Override
    public S trigger(E event) {
        return delegate.trigger(event);
    }

    @Override
    public boolean canTrigger(E event) {
        return delegate.canTrigger(event);
    }

    @Override
    public Set<E> enabledEvents() {
        return delegate.enabledEvents();
    }

    @Override
    public Set<S> reachableFrom(S state) {
        return delegate.reachableFrom(state);
    }

    @Override
    public boolean isTerminal(S state) {
        return delegate.isTerminal(state);
    }

    @Override
    public List<Transition<S, E>> transitions() {
        return delegate.transitions();
    }

    // -------------------------------------------------------------------------
    // Enum-specific diagnostics (topology only — guards are not evaluated)
    // -------------------------------------------------------------------------

    /**
     * Returns enum constants that are never the <em>target</em> of any
     * transition and are also not the initial state. Such states can never be
     * entered after the machine starts.
     *
     * <p>A non-empty set is usually a modelling error.</p>
     */
    public Set<S> unreachableStates() {
        Set<S> targets = delegate.transitions().stream()
                .map(Transition::to)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(stateClass)));
        targets.add(delegate.currentState());
        Set<S> unreachable = EnumSet.allOf(stateClass);
        unreachable.removeAll(targets);
        return unreachable;
    }

    /**
     * Returns non-terminal states that have no outgoing transition (dead ends).
     *
     * <p>A non-empty set usually signals a missing transition definition.</p>
     */
    public Set<S> deadEndStates() {
        Set<S> sources = delegate.transitions().stream()
                .map(Transition::from)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(stateClass)));
        Set<S> deadEnds = EnumSet.allOf(stateClass);
        deadEnds.removeAll(sources);
        deadEnds.removeIf(this::isTerminal);
        return deadEnds;
    }

    /**
     * Returns the fraction of all enum constants that appear in at least one
     * transition (as source or target). A value of {@code 1.0} means every
     * enum constant participates in the graph.
     */
    public double coverage() {
        Set<S> participating = delegate.transitions().stream()
                .flatMap(t -> Stream.of(t.from(), t.to()))
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(stateClass)));
        return (double) participating.size() / allStates.size();
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    /**
     * Returns a builder wired to the given enum state class.
     *
     * @param stateClass the enum class for states S
     * @param <S>        enum state type
     * @param <E>        event type
     */
    public static <S extends Enum<S>, E> Builder<S, E> builder(Class<S> stateClass) {
        return new Builder<>(stateClass);
    }

    /**
     * Fluent builder that produces an {@link EnumStateMachine}.
     *
     * @param <S> enum state type
     * @param <E> event type
     */
    public static final class Builder<S extends Enum<S>, E> {

        private final Class<S> stateClass;
        private final StateMachineBuilder<S, E> inner = StateMachineBuilder.create();

        private Builder(Class<S> stateClass) {
            this.stateClass = stateClass;
        }

        /** @see StateMachineBuilder#transition(Object, Object, Object) */
        public Builder<S, E> transition(S from, E event, S to) {
            inner.transition(from, event, to);
            return this;
        }

        /** @see StateMachineBuilder#transition(Object, Object, Object, BooleanSupplier) */
        public Builder<S, E> transition(S from, E event, S to, BooleanSupplier guard) {
            inner.transition(from, event, to, guard);
            return this;
        }

        /** @see StateMachineBuilder#transition(Object, Object, Object, BooleanSupplier, BiConsumer) */
        public Builder<S, E> transition(
                S from, E event, S to, BooleanSupplier guard, BiConsumer<S, S> onTransit) {
            inner.transition(from, event, to, guard, onTransit);
            return this;
        }

        /**
         * Marks one or more states as terminal (accepting).
         *
         * @see StateMachineBuilder#terminal(Object[])
         */
        @SafeVarargs
        @SuppressWarnings("varargs")
        public final Builder<S, E> terminal(S... states) {
            inner.terminal(states);
            return this;
        }

        /**
         * Builds and returns the {@link EnumStateMachine}.
         *
         * @param initialState the starting state
         */
        public EnumStateMachine<S, E> buildEnum(S initialState) {
            return new EnumStateMachine<>(inner.build(initialState), stateClass);
        }
    }
}
