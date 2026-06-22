package dev.tessera.statemachine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link EnumStateMachine} and its diagnostic methods.
 */
@DisplayName("EnumStateMachine — enum state machine")
class EnumStateMachineTest {

    enum OrderStatus { PLACED, PAID, SHIPPED, DELIVERED, CANCELLED }
    enum OrderEvent  { PAY, SHIP, DELIVER, CANCEL }

    private EnumStateMachine<OrderStatus, OrderEvent> buildOrderMachine() {
        return EnumStateMachine.<OrderStatus, OrderEvent>builder(OrderStatus.class)
                .transition(OrderStatus.PLACED,    OrderEvent.PAY,     OrderStatus.PAID)
                .transition(OrderStatus.PLACED,    OrderEvent.CANCEL,  OrderStatus.CANCELLED)
                .transition(OrderStatus.PAID,      OrderEvent.SHIP,    OrderStatus.SHIPPED)
                .transition(OrderStatus.PAID,      OrderEvent.CANCEL,  OrderStatus.CANCELLED)
                .transition(OrderStatus.SHIPPED,   OrderEvent.DELIVER, OrderStatus.DELIVERED)
                .terminal(OrderStatus.DELIVERED, OrderStatus.CANCELLED)
                .buildEnum(OrderStatus.PLACED);
    }

    @Test
    @DisplayName("initial state is PLACED")
    void initialState() {
        assertThat(buildOrderMachine().currentState()).isEqualTo(OrderStatus.PLACED);
    }

    @Test
    @DisplayName("trigger() advances through happy-path: PLACED→PAID→SHIPPED→DELIVERED")
    void happyPath() {
        EnumStateMachine<OrderStatus, OrderEvent> sm = buildOrderMachine();
        sm.trigger(OrderEvent.PAY);
        sm.trigger(OrderEvent.SHIP);
        sm.trigger(OrderEvent.DELIVER);
        assertThat(sm.currentState()).isEqualTo(OrderStatus.DELIVERED);
        assertThat(sm.isTerminal()).isTrue();
    }

    @Test
    @DisplayName("trigger() follows cancellation path from PLACED")
    void cancelFromPlaced() {
        EnumStateMachine<OrderStatus, OrderEvent> sm = buildOrderMachine();
        sm.trigger(OrderEvent.CANCEL);
        assertThat(sm.currentState()).isEqualTo(OrderStatus.CANCELLED);
        assertThat(sm.isTerminal()).isTrue();
    }

    @Test
    @DisplayName("trigger() throws on invalid transition in terminal state")
    void triggerInTerminal_throws() {
        EnumStateMachine<OrderStatus, OrderEvent> sm = buildOrderMachine();
        sm.trigger(OrderEvent.PAY);
        sm.trigger(OrderEvent.SHIP);
        sm.trigger(OrderEvent.DELIVER);

        assertThatThrownBy(() -> sm.trigger(OrderEvent.CANCEL))
                .isInstanceOf(IllegalTransitionException.class);
    }

    @Test
    @DisplayName("canTrigger() returns false when no transition defined")
    void canTrigger_false() {
        EnumStateMachine<OrderStatus, OrderEvent> sm = buildOrderMachine();
        sm.trigger(OrderEvent.PAY);
        sm.trigger(OrderEvent.SHIP);
        assertThat(sm.canTrigger(OrderEvent.CANCEL)).isFalse();
        assertThat(sm.canTrigger(OrderEvent.DELIVER)).isTrue();
    }

    @Test
    @DisplayName("enabledEvents() from PLACED returns PAY and CANCEL")
    void enabledEvents_fromPlaced() {
        assertThat(buildOrderMachine().enabledEvents())
                .containsExactlyInAnyOrder(OrderEvent.PAY, OrderEvent.CANCEL);
    }

    @Test
    @DisplayName("reachableFrom(PAID) returns SHIPPED and CANCELLED")
    void reachableFrom_paid() {
        assertThat(buildOrderMachine().reachableFrom(OrderStatus.PAID))
                .containsExactlyInAnyOrder(OrderStatus.SHIPPED, OrderStatus.CANCELLED);
    }

    @Test
    @DisplayName("isTerminal(DELIVERED) and isTerminal(CANCELLED) are true")
    void isTerminal_terminalStates() {
        EnumStateMachine<OrderStatus, OrderEvent> sm = buildOrderMachine();
        assertThat(sm.isTerminal(OrderStatus.DELIVERED)).isTrue();
        assertThat(sm.isTerminal(OrderStatus.CANCELLED)).isTrue();
    }

    @Test
    @DisplayName("isTerminal(PLACED) is false")
    void isTerminal_nonTerminal() {
        assertThat(buildOrderMachine().isTerminal(OrderStatus.PLACED)).isFalse();
    }

    @Test
    @DisplayName("unreachableStates() is empty when all states participate")
    void unreachableStates_allReachable() {
        assertThat(buildOrderMachine().unreachableStates()).isEmpty();
    }

    @Test
    @DisplayName("unreachableStates() detects an orphaned enum constant")
    void unreachableStates_orphan() {
        EnumStateMachine<OrderStatus, OrderEvent> sm =
                EnumStateMachine.<OrderStatus, OrderEvent>builder(OrderStatus.class)
                        .transition(OrderStatus.PLACED, OrderEvent.PAY,     OrderStatus.PAID)
                        .transition(OrderStatus.PAID,   OrderEvent.SHIP,    OrderStatus.SHIPPED)
                        .transition(OrderStatus.SHIPPED, OrderEvent.DELIVER, OrderStatus.DELIVERED)
                        .terminal(OrderStatus.DELIVERED)
                        .buildEnum(OrderStatus.PLACED);

        assertThat(sm.unreachableStates()).containsExactlyInAnyOrder(OrderStatus.CANCELLED);
    }

    @Test
    @DisplayName("deadEndStates() is empty in the full order machine")
    void deadEndStates_noneInFullMachine() {
        assertThat(buildOrderMachine().deadEndStates()).isEmpty();
    }

    @Test
    @DisplayName("deadEndStates() detects non-terminal state with no outgoing transition")
    void deadEndStates_detected() {
        EnumStateMachine<OrderStatus, OrderEvent> sm =
                EnumStateMachine.<OrderStatus, OrderEvent>builder(OrderStatus.class)
                        .transition(OrderStatus.PLACED, OrderEvent.PAY,  OrderStatus.PAID)
                        .transition(OrderStatus.PAID,   OrderEvent.SHIP, OrderStatus.SHIPPED)
                        .terminal(OrderStatus.DELIVERED, OrderStatus.CANCELLED)
                        .buildEnum(OrderStatus.PLACED);

        assertThat(sm.deadEndStates()).containsExactlyInAnyOrder(OrderStatus.SHIPPED);
    }

    @Test
    @DisplayName("coverage() returns 1.0 when all enum states appear in transitions")
    void coverage_full() {
        assertThat(buildOrderMachine().coverage()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("coverage() is less than 1.0 when some states are absent from transitions")
    void coverage_partial() {
        EnumStateMachine<OrderStatus, OrderEvent> sm =
                EnumStateMachine.<OrderStatus, OrderEvent>builder(OrderStatus.class)
                        .transition(OrderStatus.PLACED, OrderEvent.PAY,     OrderStatus.PAID)
                        .transition(OrderStatus.PAID,   OrderEvent.SHIP,    OrderStatus.SHIPPED)
                        .transition(OrderStatus.SHIPPED, OrderEvent.DELIVER, OrderStatus.DELIVERED)
                        .terminal(OrderStatus.DELIVERED)
                        .buildEnum(OrderStatus.PLACED);

        assertThat(sm.coverage()).isEqualTo(0.8);
    }

    @Test
    @DisplayName("guard on enum transition blocks trigger and canTrigger returns false")
    void enumMachine_guard() {
        boolean[] paymentVerified = {false};

        EnumStateMachine<OrderStatus, OrderEvent> sm =
                EnumStateMachine.<OrderStatus, OrderEvent>builder(OrderStatus.class)
                        .transition(
                                OrderStatus.PLACED, OrderEvent.PAY, OrderStatus.PAID,
                                () -> paymentVerified[0])
                        .terminal(OrderStatus.PAID)
                        .buildEnum(OrderStatus.PLACED);

        assertThat(sm.canTrigger(OrderEvent.PAY)).isFalse();
        assertThatThrownBy(() -> sm.trigger(OrderEvent.PAY))
                .isInstanceOf(GuardRejectedException.class);

        paymentVerified[0] = true;
        assertThat(sm.canTrigger(OrderEvent.PAY)).isTrue();
        assertThat(sm.trigger(OrderEvent.PAY)).isEqualTo(OrderStatus.PAID);
    }

    @Test
    @DisplayName("transitions() returns all five registered transitions")
    void transitions_count() {
        assertThat(buildOrderMachine().transitions()).hasSize(5);
    }
}
