package dev.tessera.statemachine;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Package-private implementation of {@link StateMachine}.
 *
 * <p>Transitions are indexed as {@code Map<S, Map<E, Transition<S,E>>>} for
 * O(1) lookup by (state, event). The state is mutable via {@link #trigger};
 * all other operations are pure queries.</p>
 */
final class DefaultStateMachine<S, E> implements StateMachine<S, E> {

    private final Map<S, Map<E, Transition<S, E>>> index;
    private final List<Transition<S, E>> allTransitions;
    private final Set<S> terminalStates;
    private S current;

    DefaultStateMachine(
            List<Transition<S, E>> transitions,
            Set<S> terminalStates,
            S initialState) {
        this.allTransitions = List.copyOf(transitions);
        this.terminalStates = Set.copyOf(terminalStates);
        this.current = initialState;

        Map<S, Map<E, Transition<S, E>>> idx = new HashMap<>();
        for (Transition<S, E> t : transitions) {
            idx.computeIfAbsent(t.from(), k -> new LinkedHashMap<>())
               .put(t.event(), t);
        }
        this.index = Collections.unmodifiableMap(idx);
    }

    @Override
    public S currentState() {
        return current;
    }

    @Override
    public S trigger(E event) {
        Map<E, Transition<S, E>> byEvent = index.get(current);
        Set<E> available = byEvent == null ? Set.of() : byEvent.keySet();

        if (byEvent == null || !byEvent.containsKey(event)) {
            throw new IllegalTransitionException(current, event, available);
        }
        Transition<S, E> t = byEvent.get(event);
        if (!t.guardPasses()) {
            throw new GuardRejectedException(current, event, t.to());
        }
        current = t.to();
        t.fireCallback();
        return current;
    }

    @Override
    public boolean canTrigger(E event) {
        Map<E, Transition<S, E>> byEvent = index.get(current);
        if (byEvent == null || !byEvent.containsKey(event)) {
            return false;
        }
        return byEvent.get(event).guardPasses();
    }

    @Override
    public Set<E> enabledEvents() {
        Map<E, Transition<S, E>> byEvent = index.get(current);
        if (byEvent == null) {
            return Set.of();
        }
        Set<E> enabled = new HashSet<>();
        for (Map.Entry<E, Transition<S, E>> entry : byEvent.entrySet()) {
            if (entry.getValue().guardPasses()) {
                enabled.add(entry.getKey());
            }
        }
        return Collections.unmodifiableSet(enabled);
    }

    @Override
    public Set<S> reachableFrom(S state) {
        Map<E, Transition<S, E>> byEvent = index.get(state);
        if (byEvent == null) {
            return Set.of();
        }
        Set<S> targets = new HashSet<>();
        for (Transition<S, E> t : byEvent.values()) {
            targets.add(t.to());
        }
        return Collections.unmodifiableSet(targets);
    }

    @Override
    public boolean isTerminal(S state) {
        return terminalStates.contains(state);
    }

    @Override
    public List<Transition<S, E>> transitions() {
        return allTransitions;
    }
}
