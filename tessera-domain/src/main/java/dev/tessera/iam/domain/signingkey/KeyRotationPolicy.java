package dev.tessera.iam.domain.signingkey;

import dev.tessera.statemachine.EnumStateMachine;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The pure rotation policy / state machine governing a token signing key's lifecycle.
 *
 * <p>It is a stateless functional core: every method is a total function of its
 * arguments, it reads no clock and touches no I/O. Time is always supplied by the
 * caller, so the same inputs always yield the same decision and the policy is trivially
 * unit-testable.
 *
 * <h2>Lifecycle</h2>
 * The only legal progression is, strictly forward:
 * <pre>PENDING &rarr; ACTIVE &rarr; RETIRING &rarr; RETIRED</pre>
 * No transition may skip a state or move backwards. The topology is declared once on
 * the framework-free {@link EnumStateMachine} (see {@link #LIFECYCLE}) and is the single
 * source of truth for {@link #isLegalTransition}, rather than a hand-rolled table.
 *
 * <h2>Two invariants</h2>
 * <ul>
 *   <li><b>publish-before-sign</b> — a key may only sign once it has been published.
 *       A key is first published while {@code PENDING} (it appears in the JWKS so
 *       verifiers can pre-trust it), and may become {@code ACTIVE} (the sole signing
 *       state) <em>only</em> from {@code PENDING}. Thus no key ever signs a token that
 *       a verifier could not already have fetched the public key for.</li>
 *   <li><b>retire-after-max-TTL</b> — given a maximum signing TTL and a clock instant,
 *       an {@code ACTIVE} key whose age exceeds the TTL is due to step down to
 *       {@code RETIRING}, and a {@code RETIRING} key that has been published long
 *       enough is due to step to {@code RETIRED}. The policy only <em>decides</em>;
 *       the caller applies the move.</li>
 * </ul>
 *
 * <h2>JWKS publication</h2>
 * {@link #publishedJwks(List)} returns every <em>publishable</em> key — the
 * {@code PENDING}, {@code ACTIVE} and {@code RETIRING} public keys. A key is published
 * while {@code PENDING}, before it is promoted to {@code ACTIVE} and signs, so a verifier
 * can pre-trust it (publish-before-sign); {@code RETIRING} keys stay published so that
 * tokens signed just before a rotation still verify against the JWKS. Only
 * {@code RETIRED} keys are withdrawn.
 */
public final class KeyRotationPolicy {

    private KeyRotationPolicy() {
    }

    /**
     * Lifecycle events driving the signing-key machine — each is exactly one forward
     * edge of {@link #LIFECYCLE}.
     */
    public enum RotationEvent {
        /** PENDING &rarr; ACTIVE: a published key is promoted to the sole signing key. */
        ACTIVATE,
        /** ACTIVE &rarr; RETIRING: the key stops signing but stays published to verify. */
        RETIRE,
        /** RETIRING &rarr; RETIRED: the key is withdrawn from the JWKS. */
        EXPIRE
    }

    /**
     * The canonical lifecycle topology, declared once on the platform's framework-free
     * {@link EnumStateMachine}: the strictly-forward chain
     * PENDING &rarr; ACTIVE &rarr; RETIRING &rarr; RETIRED, with RETIRED terminal. This is
     * the single source of truth for {@link #isLegalTransition}; its enum diagnostics
     * (full coverage, no dead-ends, nothing unreachable) are asserted by the policy test.
     */
    private static final EnumStateMachine<SigningKeyState, RotationEvent> LIFECYCLE =
            EnumStateMachine.<SigningKeyState, RotationEvent>builder(SigningKeyState.class)
                    .transition(SigningKeyState.PENDING, RotationEvent.ACTIVATE, SigningKeyState.ACTIVE)
                    .transition(SigningKeyState.ACTIVE, RotationEvent.RETIRE, SigningKeyState.RETIRING)
                    .transition(SigningKeyState.RETIRING, RotationEvent.EXPIRE, SigningKeyState.RETIRED)
                    .terminal(SigningKeyState.RETIRED)
                    .buildEnum(SigningKeyState.PENDING);

    /**
     * Exposes the lifecycle topology (read-only) for diagnostics and tests. The returned
     * machine is queried for topology only; its state is never advanced.
     */
    static EnumStateMachine<SigningKeyState, RotationEvent> lifecycle() {
        return LIFECYCLE;
    }

    /**
     * Whether {@code from -> to} is a legal lifecycle transition, decided against the
     * shared {@link #LIFECYCLE} topology (one transition, guards irrelevant here).
     *
     * <p>Only the strictly-forward steps PENDING&rarr;ACTIVE, ACTIVE&rarr;RETIRING and
     * RETIRING&rarr;RETIRED are legal. Encodes <b>publish-before-sign</b>: ACTIVE (the
     * signing state) is reachable only from PENDING (the first published state).
     */
    public static boolean isLegalTransition(SigningKeyState from, SigningKeyState to) {
        return LIFECYCLE.reachableFrom(from).contains(to);
    }

    /**
     * Applies a transition, throwing {@link IllegalStateException} if it is illegal.
     *
     * @param from the current state
     * @param to   the requested next state
     * @return {@code to} when the transition is legal
     */
    public static SigningKeyState transition(SigningKeyState from, SigningKeyState to) {
        if (!isLegalTransition(from, to)) {
            throw new IllegalStateException(
                    "Illegal signing-key transition " + from + " -> " + to);
        }
        return to;
    }

    /**
     * Whether a key in {@code state} is allowed to sign newly issued tokens. Only an
     * {@code ACTIVE} key may sign (publish-before-sign: it reached ACTIVE via PENDING).
     */
    public static boolean canSign(SigningKeyState state) {
        return switch (state) {
            case PENDING, RETIRING, RETIRED -> false;
            case ACTIVE -> true;
        };
    }

    /**
     * Whether a key in {@code state} is published in the JWKS. {@code PENDING},
     * {@code ACTIVE} and {@code RETIRING} keys are published; only {@code RETIRED} keys
     * are withdrawn. {@code PENDING} keys are pre-published so a verifier can trust them
     * before they sign (publish-before-sign).
     *
     * <p>This is the single per-state publication predicate; {@link #publishedJwks(List)}
     * selects exactly the keys for which this returns {@code true}.
     */
    public static boolean isPublishable(SigningKeyState state) {
        return switch (state) {
            case PENDING, ACTIVE, RETIRING -> true;
            case RETIRED -> false;
        };
    }

    /**
     * Decides whether an {@code ACTIVE} key is due to step down to {@code RETIRING}
     * because it has out-lived the maximum signing TTL.
     *
     * @param descriptor the key under consideration
     * @param maxSigningTtl the maximum age an ACTIVE key may sign for
     * @param now the current instant (supplied by the caller — the policy reads no clock)
     * @return {@code true} iff the key is ACTIVE, has an activation instant, and its age
     *     at {@code now} is at least {@code maxSigningTtl}
     */
    public static boolean isDueForRetiring(
            SigningKeyDescriptor descriptor, Duration maxSigningTtl, Instant now) {
        if (descriptor.state() != SigningKeyState.ACTIVE || descriptor.activatedAt() == null) {
            return false;
        }
        Duration age = Duration.between(descriptor.activatedAt(), now);
        return age.compareTo(maxSigningTtl) >= 0;
    }

    /**
     * Decides whether a {@code RETIRING} key is due to step to {@code RETIRED} because
     * it has been published (in the verification window) at least {@code retiringGrace}
     * past its activation — i.e. no live token can still reference it.
     *
     * @param descriptor the key under consideration
     * @param maxSigningTtl the maximum signing age (the first segment of the window)
     * @param retiringGrace how long a key stays published after it stops signing
     * @param now the current instant (supplied by the caller)
     * @return {@code true} iff the key is RETIRING and its age exceeds
     *     {@code maxSigningTtl + retiringGrace}
     */
    public static boolean isDueForRetired(
            SigningKeyDescriptor descriptor,
            Duration maxSigningTtl,
            Duration retiringGrace,
            Instant now) {
        if (descriptor.state() != SigningKeyState.RETIRING || descriptor.activatedAt() == null) {
            return false;
        }
        Duration age = Duration.between(descriptor.activatedAt(), now);
        return age.compareTo(maxSigningTtl.plus(retiringGrace)) >= 0;
    }

    /**
     * The public JWKS published for a realm: every publishable key — the
     * {@code PENDING}, {@code ACTIVE} and {@code RETIRING} public keys, in input order.
     * {@code PENDING} keys are pre-published so a verifier can trust a key before it is
     * promoted to {@code ACTIVE} and signs (publish-before-sign); {@code RETIRING} keys
     * stay published so a token signed just before a rotation still verifies. Only
     * {@code RETIRED} keys are withdrawn.
     *
     * @param keys all keys known for the realm
     * @return the published public JWKs (never {@code null})
     */
    public static List<PublicJwk> publishedJwks(List<SigningKeyDescriptor> keys) {
        List<PublicJwk> published = new ArrayList<>();
        for (SigningKeyDescriptor key : keys) {
            if (isPublishable(key.state())) {
                published.add(key.publicJwk());
            }
        }
        return List.copyOf(published);
    }

    /**
     * Selects a key by its {@code kid}, algorithm and use — the lookup a verifier
     * performs against a JWS header. Matches only published (ACTIVE or RETIRING) keys,
     * so a withdrawn or not-yet-published key is never selected.
     *
     * @param keys all keys known for the realm
     * @param keyId the requested {@code kid}
     * @param algorithm the requested algorithm
     * @param use the requested key use
     * @return the matching published key, if any
     */
    public static Optional<SigningKeyDescriptor> select(
            List<SigningKeyDescriptor> keys,
            KeyId keyId,
            SigningAlgorithm algorithm,
            KeyUse use) {
        for (SigningKeyDescriptor key : keys) {
            if (key.isPublished()
                    && key.keyId().equals(keyId)
                    && key.algorithm() == algorithm
                    && key.use() == use) {
                return Optional.of(key);
            }
        }
        return Optional.empty();
    }

    /**
     * Selects the single key that should sign newly issued tokens for a realm: the one
     * {@code ACTIVE} key. If more than one key is ACTIVE the selection is ambiguous and
     * an {@link IllegalStateException} is thrown — a realm has at most one signing key.
     *
     * @param keys all keys known for the realm
     * @return the current signing key, if a (single) ACTIVE key exists
     */
    public static Optional<SigningKeyDescriptor> currentSigningKey(
            List<SigningKeyDescriptor> keys) {
        SigningKeyDescriptor found = null;
        for (SigningKeyDescriptor key : keys) {
            if (key.state() == SigningKeyState.ACTIVE) {
                if (found != null) {
                    throw new IllegalStateException(
                            "More than one ACTIVE signing key for the realm");
                }
                found = key;
            }
        }
        return Optional.ofNullable(found);
    }
}
