/**
 * The pure authentication-flow engine for the Tessera domain
 *.
 *
 * <p>This package is the <strong>functional core</strong> of the
 * functional-core / imperative-shell design
 *. It models
 * Keycloak's authenticator-chain SPI as data + a single pure reducer, with
 * compile-time exhaustiveness in place of deploy-time wiring:
 *
 * <ul>
 *   <li>{@link dev.tessera.iam.domain.authflow.AuthStep} — a flow expressed as an
 *       ordered, sealed list of immutable step <em>values</em>.</li>
 *   <li>{@link dev.tessera.iam.domain.authflow.AuthEvent} — the verified inputs that
 *       drive the fold (raw secrets are checked in the shell, never here).</li>
 *   <li>{@link dev.tessera.iam.domain.authflow.AuthExchange} — the immutable state
 *       snapshot threaded through the flow; every transition returns a new instance.</li>
 *   <li>{@link dev.tessera.iam.domain.authflow.AuthOutcome} — the result, with
 *       {@link dev.tessera.iam.domain.authflow.AuthOutcome.Challenge} as a
 *       <em>first-class return value</em>, never an exception.</li>
 *   <li>{@link dev.tessera.iam.domain.authflow.SideEffectRequest} — data describing an
 *       effect the shell must execute; the core never performs I/O.</li>
 *   <li>{@link dev.tessera.iam.domain.authflow.AuthFlowReducer} — the total,
 *       deterministic {@code reduce(state, event)} function tying it together.</li>
 * </ul>
 *
 * <p><strong>Purity contract.</strong> {@code reduce} reads no clock and no
 * randomness; any time/nonce value is threaded in on the
 * {@link dev.tessera.iam.domain.authflow.AuthEvent}. Every type here is plain
 * {@code java..} — {@code DomainPurityTest} forbids any framework import.
 *
 * <p>The claim side is split: {@link dev.tessera.iam.domain.authflow.ClaimContributor}
 * (with {@link dev.tessera.iam.domain.authflow.ClaimContext}) is the <em>pure</em>
 * assembly of claims over already-fetched data, while the <em>async</em> fetch of
 * that data lives behind the {@code ClaimSourcePort} driven port in iam-api.
 */
package dev.tessera.iam.domain.authflow;
