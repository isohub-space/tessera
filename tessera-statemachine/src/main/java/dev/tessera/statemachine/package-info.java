/**
 * Generic, framework-free state machine for any service.
 *
 * <p><b>Value/enum machine</b> — for states that are fixed values:
 * {@link dev.tessera.statemachine.StateMachine} (interface),
 * {@link dev.tessera.statemachine.StateMachineBuilder} (fluent builder),
 * {@link dev.tessera.statemachine.EnumStateMachine} (enum-specialised
 * wrapper with diagnostics), and supporting type
 * {@link dev.tessera.statemachine.Transition}. Matched by value equality with
 * constant transition targets; mutable current state.</p>
 *
 * <p><b>Typed/record machine</b> — for states modelled as a {@code sealed} hierarchy of
 * payload-carrying {@code record} variants:
 * {@link dev.tessera.statemachine.TypedStateMachine} (interface),
 * {@link dev.tessera.statemachine.TypedStateMachineBuilder} (fluent builder), and
 * {@link dev.tessera.statemachine.Reduction} (next state + output). Routed by runtime
 * variant {@link java.lang.Class}, with reducer transitions that compute a fresh next
 * state; immutable and thread-safe. Completeness over the sealed variants is checkable via
 * {@link dev.tessera.statemachine.TypedStateMachine#uncoveredVariants()}.</p>
 *
 * <p>Both share {@link dev.tessera.statemachine.IllegalTransitionException} and
 * {@link dev.tessera.statemachine.GuardRejectedException}.</p>
 *
 * <p>Depends only on the Java standard library. The value/enum machine is not thread-safe;
 * the typed machine is immutable and thread-safe.</p>
 */
package dev.tessera.statemachine;
