package dev.tessera.statemachine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link StateMachineBuilder} and the generic {@link StateMachine}
 * behaviour it produces.
 */
@DisplayName("StateMachineBuilder — generic state machine")
class StateMachineBuilderTest {

    private static final String IDLE = "IDLE";
    private static final String RUNNING = "RUNNING";
    private static final String PAUSED = "PAUSED";
    private static final String STOPPED = "STOPPED";

    private static final String START = "START";
    private static final String PAUSE = "PAUSE";
    private static final String RESUME = "RESUME";
    private static final String STOP = "STOP";

    private StateMachine<String, String> buildSimple() {
        return StateMachineBuilder.<String, String>create()
                .transition(IDLE,    START,  RUNNING)
                .transition(RUNNING, PAUSE,  PAUSED)
                .transition(RUNNING, STOP,   STOPPED)
                .transition(PAUSED,  RESUME, RUNNING)
                .transition(PAUSED,  STOP,   STOPPED)
                .terminal(STOPPED)
                .build(IDLE);
    }

    @Test
    @DisplayName("build() sets the initial state correctly")
    void initialState() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.currentState()).isEqualTo(IDLE);
    }

    @Test
    @DisplayName("trigger() advances state on valid event")
    void trigger_advances() {
        StateMachine<String, String> sm = buildSimple();
        String next = sm.trigger(START);
        assertThat(next).isEqualTo(RUNNING);
        assertThat(sm.currentState()).isEqualTo(RUNNING);
    }

    @Test
    @DisplayName("trigger() follows multi-hop path")
    void trigger_multiHop() {
        StateMachine<String, String> sm = buildSimple();
        sm.trigger(START);
        sm.trigger(PAUSE);
        sm.trigger(RESUME);
        assertThat(sm.currentState()).isEqualTo(RUNNING);
    }

    @Test
    @DisplayName("trigger() throws IllegalTransitionException for undefined event")
    void trigger_undefinedEvent() {
        StateMachine<String, String> sm = buildSimple();
        assertThatThrownBy(() -> sm.trigger("UNKNOWN"))
                .isInstanceOf(IllegalTransitionException.class)
                .hasMessageContaining(IDLE)
                .hasMessageContaining("UNKNOWN");
    }

    @Test
    @DisplayName("trigger() in wrong state throws IllegalTransitionException")
    void trigger_wrongState() {
        StateMachine<String, String> sm = buildSimple();
        assertThatThrownBy(() -> sm.trigger(PAUSE))
                .isInstanceOf(IllegalTransitionException.class);
    }

    @Test
    @DisplayName("IllegalTransitionException carries state, event, and available events")
    void trigger_exceptionCarriesContext() {
        StateMachine<String, String> sm = buildSimple();
        try {
            sm.trigger("UNKNOWN");
        } catch (IllegalTransitionException ex) {
            assertThat(ex.fromState()).isEqualTo(IDLE);
            assertThat(ex.event()).isEqualTo("UNKNOWN");
            assertThat(ex.availableEvents()).isEqualTo(java.util.Set.of(START));
        }
    }

    @Test
    @DisplayName("trigger() throws GuardRejectedException when guard returns false")
    void trigger_guardRejected() {
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, () -> false)
                .build(IDLE);

        assertThatThrownBy(() -> sm.trigger(START))
                .isInstanceOf(GuardRejectedException.class)
                .hasMessageContaining(IDLE)
                .hasMessageContaining(START)
                .hasMessageContaining(RUNNING);
    }

    @Test
    @DisplayName("trigger() fires when guard returns true")
    void trigger_guardPasses() {
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, () -> true)
                .build(IDLE);

        assertThat(sm.trigger(START)).isEqualTo(RUNNING);
    }

    @Test
    @DisplayName("GuardRejectedException carries from/event/to context")
    void guardRejected_exceptionCarriesContext() {
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, () -> false)
                .build(IDLE);

        try {
            sm.trigger(START);
        } catch (GuardRejectedException ex) {
            assertThat(ex.fromState()).isEqualTo(IDLE);
            assertThat(ex.event()).isEqualTo(START);
            assertThat(ex.toState()).isEqualTo(RUNNING);
        }
    }

    @Test
    @DisplayName("onTransit callback receives (from, to) after state change")
    void onTransit_callback() {
        List<String> log = new ArrayList<>();
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, null,
                        (from, to) -> log.add(from + "->" + to))
                .build(IDLE);

        sm.trigger(START);
        assertThat(log).containsExactly("IDLE->RUNNING");
    }

    @Test
    @DisplayName("state is already changed when callback fires")
    void onTransit_stateAlreadyUpdated() {
        List<String> observedState = new ArrayList<>();
        AtomicReference<StateMachine<String, String>> ref = new AtomicReference<>();
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, null,
                        (from, to) -> observedState.add(ref.get().currentState()))
                .build(IDLE);
        ref.set(sm);
        sm.trigger(START);
        assertThat(observedState).containsExactly(RUNNING);
    }

    @Test
    @DisplayName("canTrigger() returns true for defined, guard-passing transition")
    void canTrigger_true() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.canTrigger(START)).isTrue();
    }

    @Test
    @DisplayName("canTrigger() returns false for undefined transition")
    void canTrigger_falseUndefined() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.canTrigger(PAUSE)).isFalse();
    }

    @Test
    @DisplayName("canTrigger() returns false when guard rejects")
    void canTrigger_guardRejects() {
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, START, RUNNING, () -> false)
                .build(IDLE);
        assertThat(sm.canTrigger(START)).isFalse();
    }

    @Test
    @DisplayName("enabledEvents() returns all events with passing guards")
    void enabledEvents_normal() {
        StateMachine<String, String> sm = buildSimple();
        sm.trigger(START);
        assertThat(sm.enabledEvents()).containsExactlyInAnyOrder(PAUSE, STOP);
    }

    @Test
    @DisplayName("enabledEvents() excludes events whose guard rejects")
    void enabledEvents_excludesRejected() {
        boolean[] flag = {false};
        StateMachine<String, String> sm = StateMachineBuilder.<String, String>create()
                .transition(IDLE, "A", RUNNING, () -> true)
                .transition(IDLE, "B", RUNNING, () -> flag[0])
                .build(IDLE);

        assertThat(sm.enabledEvents()).containsExactly("A");
        flag[0] = true;
        assertThat(sm.enabledEvents()).containsExactlyInAnyOrder("A", "B");
    }

    @Test
    @DisplayName("enabledEvents() is empty in terminal state with no outgoing transitions")
    void enabledEvents_emptyInTerminal() {
        StateMachine<String, String> sm = buildSimple();
        sm.trigger(START);
        sm.trigger(STOP);
        assertThat(sm.enabledEvents()).isEmpty();
    }

    @Test
    @DisplayName("reachableFrom() returns correct target states")
    void reachableFrom() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.reachableFrom(RUNNING)).containsExactlyInAnyOrder(PAUSED, STOPPED);
    }

    @Test
    @DisplayName("reachableFrom() returns empty set for state with no outgoing transitions")
    void reachableFrom_terminal() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.reachableFrom(STOPPED)).isEmpty();
    }

    @Test
    @DisplayName("isTerminal(state) returns true for declared terminal states")
    void isTerminal_declared() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.isTerminal(STOPPED)).isTrue();
        assertThat(sm.isTerminal(IDLE)).isFalse();
    }

    @Test
    @DisplayName("isTerminal() (no-arg) checks current state")
    void isTerminal_current() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.isTerminal()).isFalse();
        sm.trigger(START);
        sm.trigger(STOP);
        assertThat(sm.isTerminal()).isTrue();
    }

    @Test
    @DisplayName("transitions() returns all registered transitions")
    void transitions_count() {
        StateMachine<String, String> sm = buildSimple();
        assertThat(sm.transitions()).hasSize(5);
    }

    @Test
    @DisplayName("build() throws when no transitions are registered")
    void build_noTransitions() {
        assertThatThrownBy(() ->
                StateMachineBuilder.<String, String>create().build(IDLE))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
