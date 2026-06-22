package dev.tessera.statemachine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("TypedStateMachine — sealed-record reducer with completeness checking")
class TypedStateMachineTest {

    // --- A faithful sample: a login flow whose steps are payload-carrying records. ---

    sealed interface LoginStep
            permits Identify, VerifyPassword, RequireMfa, Authenticated, Denied {
    }

    record Identify() implements LoginStep {
    }

    record VerifyPassword(String user, int attempts) implements LoginStep {
    }

    record RequireMfa(String user) implements LoginStep {
    }

    record Authenticated(String user) implements LoginStep {
    }

    record Denied(String reason) implements LoginStep {
    }

    enum LoginEvent {
        SUBMIT_ID, GOOD_PASSWORD, BAD_PASSWORD, MFA_OK
    }

    record Outcome(String note) {
    }

    private static final int MAX_ATTEMPTS = 3;

    /** The full machine — every variant handled or terminal, so buildStrict() succeeds. */
    private static TypedStateMachine<LoginStep, LoginEvent, Outcome> loginMachine() {
        return TypedStateMachineBuilder.<LoginStep, LoginEvent, Outcome>create(LoginStep.class)
                .on(Identify.class,
                        (s, e) -> Reduction.of(new VerifyPassword("alice", 0), new Outcome("ask-password")))
                // Guarded: after MAX_ATTEMPTS the variant is locked out (guard rejects).
                .on(VerifyPassword.class,
                        (VerifyPassword s, LoginEvent e) -> s.attempts() < MAX_ATTEMPTS,
                        (VerifyPassword s, LoginEvent e) -> switch (e) {
                            case GOOD_PASSWORD ->
                                    Reduction.of(new RequireMfa(s.user()), new Outcome("ask-mfa"));
                            case BAD_PASSWORD ->
                                    Reduction.of(new VerifyPassword(s.user(), s.attempts() + 1),
                                            new Outcome("retry"));
                            default -> throw new IllegalTransitionException(s, e);
                        })
                .on(RequireMfa.class,
                        (RequireMfa s, LoginEvent e) ->
                                Reduction.of(new Authenticated(s.user()), new Outcome("done")))
                .terminal(Authenticated.class, Denied.class)
                .buildStrict();
    }

    @Nested
    @DisplayName("routing by variant type")
    class Routing {

        @Test
        @DisplayName("routes on the runtime variant and builds a payload-carrying next state")
        void routesAndCarriesPayload() {
            var machine = loginMachine();

            Reduction<LoginStep, Outcome> r =
                    machine.step(new Identify(), LoginEvent.SUBMIT_ID);

            assertThat(r.nextState()).isEqualTo(new VerifyPassword("alice", 0));
            assertThat(r.output()).isEqualTo(new Outcome("ask-password"));
        }

        @Test
        @DisplayName("same variant, different payload routes to the same handler")
        void payloadDoesNotAffectRouting() {
            var machine = loginMachine();

            var r0 = machine.step(new VerifyPassword("alice", 0), LoginEvent.BAD_PASSWORD);
            var r1 = machine.step(new VerifyPassword("alice", 2), LoginEvent.BAD_PASSWORD);

            assertThat(r0.nextState()).isEqualTo(new VerifyPassword("alice", 1));
            assertThat(r1.nextState()).isEqualTo(new VerifyPassword("alice", 3));
        }

        @Test
        @DisplayName("a good password advances to MFA")
        void advancesToMfa() {
            var machine = loginMachine();
            var r = machine.step(new VerifyPassword("alice", 1), LoginEvent.GOOD_PASSWORD);
            assertThat(r.nextState()).isEqualTo(new RequireMfa("alice"));
        }

        @Test
        @DisplayName("an event the handler does not accept throws IllegalTransitionException")
        void unhandledEventInReducer() {
            var machine = loginMachine();
            assertThatThrownBy(
                    () -> machine.step(new VerifyPassword("alice", 0), LoginEvent.MFA_OK))
                    .isInstanceOf(IllegalTransitionException.class);
        }
    }

    @Nested
    @DisplayName("guards, terminals and illegal transitions")
    class GuardsAndTerminals {

        @Test
        @DisplayName("a rejecting guard throws GuardRejectedException and skips the reducer")
        void guardRejects() {
            var machine = loginMachine();
            var lockedOut = new VerifyPassword("alice", MAX_ATTEMPTS);

            assertThat(machine.canStep(lockedOut, LoginEvent.GOOD_PASSWORD)).isFalse();
            assertThatThrownBy(() -> machine.step(lockedOut, LoginEvent.GOOD_PASSWORD))
                    .isInstanceOf(GuardRejectedException.class);
        }

        @Test
        @DisplayName("canStep is true when a handler exists and its guard passes")
        void canStepWhenGuardPasses() {
            var machine = loginMachine();
            assertThat(machine.canStep(new VerifyPassword("alice", 0), LoginEvent.GOOD_PASSWORD))
                    .isTrue();
        }

        @Test
        @DisplayName("a terminal variant is terminal and cannot be stepped")
        void terminalCannotStep() {
            var machine = loginMachine();
            var done = new Authenticated("alice");

            assertThat(machine.isTerminal(done)).isTrue();
            assertThat(machine.isTerminal(new Identify())).isFalse();
            assertThat(machine.canStep(done, LoginEvent.MFA_OK)).isFalse();
            assertThatThrownBy(() -> machine.step(done, LoginEvent.MFA_OK))
                    .isInstanceOf(IllegalTransitionException.class);
        }
    }

    @Nested
    @DisplayName("completeness over the sealed variants")
    class Completeness {

        @Test
        @DisplayName("a fully-covered machine has no uncovered variants and buildStrict succeeds")
        void fullyCovered() {
            assertThat(loginMachine().uncoveredVariants()).isEmpty();
            assertThat(loginMachine().coveredVariants())
                    .contains(Identify.class, VerifyPassword.class, RequireMfa.class);
        }

        @Test
        @DisplayName("an omitted variant is reported and buildStrict refuses to build")
        void omittedVariantDetected() {
            var partial = TypedStateMachineBuilder
                    .<LoginStep, LoginEvent, Outcome>create(LoginStep.class)
                    .on(Identify.class,
                            (s, e) -> Reduction.to(new Authenticated("alice")))
                    .terminal(Authenticated.class, Denied.class);
            // VerifyPassword and RequireMfa are neither handled nor terminal.

            assertThat(partial.build().uncoveredVariants())
                    .containsExactlyInAnyOrder(VerifyPassword.class, RequireMfa.class);
            assertThatThrownBy(partial::buildStrict)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("uncovered variants");
        }
    }

    // --- Leaf recursion through nested sealed types. ---

    sealed interface Shape permits Circle, Poly {
    }

    record Circle() implements Shape {
    }

    sealed interface Poly extends Shape permits Triangle, Square {
    }

    record Triangle() implements Poly {
    }

    record Square() implements Poly {
    }

    @Test
    @DisplayName("permittedLeaves expands nested sealed types down to concrete leaves")
    void permittedLeavesRecurses() {
        assertThat(DefaultTypedStateMachine.permittedLeaves(Shape.class))
                .containsExactlyInAnyOrder(Circle.class, Triangle.class, Square.class);
    }

    @Test
    @DisplayName("a non-sealed state type yields no completeness information")
    void nonSealedYieldsNoLeaves() {
        assertThat(DefaultTypedStateMachine.permittedLeaves(Object.class)).isEmpty();
    }
}
