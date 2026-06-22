package dev.tessera.statemachine;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.BiPredicate;

/**
 * Package-private implementation of {@link TypedStateMachine}.
 *
 * <p>Handlers are indexed by the state's variant {@link Class} for O(1) routing. The
 * machine is immutable and holds no current state — {@link #step} is a pure function.</p>
 *
 * @param <S> state type
 * @param <E> event type
 * @param <O> output type
 */
final class DefaultTypedStateMachine<S, E, O> implements TypedStateMachine<S, E, O> {

    /**
     * One registered variant handler: an optional guard plus the reducer that computes
     * the {@link Reduction}. Both operate on the base types; the builder guarantees they
     * are only ever invoked with a state of the keyed variant.
     */
    record Handler<S, E, O>(
            BiPredicate<S, E> guard, BiFunction<S, E, Reduction<S, O>> reducer) {
    }

    private final Class<S> stateType;
    private final Map<Class<? extends S>, Handler<S, E, O>> handlers;
    private final Set<Class<? extends S>> terminals;

    DefaultTypedStateMachine(
            Class<S> stateType,
            Map<Class<? extends S>, Handler<S, E, O>> handlers,
            Set<Class<? extends S>> terminals) {
        this.stateType = stateType;
        this.handlers = Map.copyOf(handlers);
        this.terminals = Set.copyOf(terminals);
    }

    @Override
    public Reduction<S, O> step(S state, E event) {
        Handler<S, E, O> handler = handlers.get(variantOf(state));
        if (handler == null) {
            throw new IllegalTransitionException(state, event);
        }
        if (handler.guard() != null && !handler.guard().test(state, event)) {
            throw new GuardRejectedException(state, event);
        }
        return handler.reducer().apply(state, event);
    }

    @Override
    public boolean canStep(S state, E event) {
        Handler<S, E, O> handler = handlers.get(variantOf(state));
        if (handler == null) {
            return false;
        }
        return handler.guard() == null || handler.guard().test(state, event);
    }

    @Override
    public boolean isTerminal(S state) {
        return terminals.contains(variantOf(state));
    }

    @Override
    public Set<Class<? extends S>> coveredVariants() {
        return handlers.keySet();
    }

    @Override
    public Set<Class<? extends S>> uncoveredVariants() {
        Set<Class<? extends S>> missing = new LinkedHashSet<>(permittedLeaves(stateType));
        missing.removeAll(handlers.keySet());
        missing.removeAll(terminals);
        return Collections.unmodifiableSet(missing);
    }

    private Class<? extends S> variantOf(S state) {
        Objects.requireNonNull(state, "state must not be null");
        return state.getClass().asSubclass(stateType);
    }

    /**
     * The concrete leaf variants of a sealed {@code root}: each permitted subclass that is
     * itself sealed is expanded to its own permitted subclasses, recursively, so only the
     * final/record leaves remain. Returns an empty set if {@code root} is not sealed.
     */
    static <S> Set<Class<? extends S>> permittedLeaves(Class<S> root) {
        if (!root.isSealed()) {
            return Set.of();
        }
        Set<Class<? extends S>> leaves = new LinkedHashSet<>();
        collectLeaves(root, leaves);
        return leaves;
    }

    private static <S> void collectLeaves(Class<? extends S> type, Set<Class<? extends S>> acc) {
        if (type.isSealed()) {
            for (Class<?> permitted : type.getPermittedSubclasses()) {
                @SuppressWarnings("unchecked")
                Class<? extends S> sub = (Class<? extends S>) permitted;
                collectLeaves(sub, acc);
            }
        } else {
            acc.add(type);
        }
    }
}
