package dev.tessera.iam.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("KeyRotationPolicy — pure four-state rotation rules")
class KeyRotationPolicyTest {

    private static final Instant T0 = Instant.parse("2026-06-22T00:00:00Z");
    private static final Duration MAX_TTL = Duration.ofHours(24);
    private static final Duration GRACE = Duration.ofHours(12);

    private static PublicJwk jwk(String kid) {
        return new PublicJwk(
                KeyId.of(kid), SigningAlgorithm.EdDSA, KeyUse.SIGNATURE, "x-" + kid, null);
    }

    private static SigningKeyDescriptor key(String kid, SigningKeyState state, Instant activated) {
        return new SigningKeyDescriptor(KeyId.of(kid), jwk(kid), state, activated);
    }

    @Nested
    @DisplayName("lifecycle topology (shared EnumStateMachine)")
    class Topology {

        @Test
        @DisplayName("every state participates: full coverage, no dead-ends, nothing unreachable")
        void topologyIsWellFormed() {
            var machine = KeyRotationPolicy.lifecycle();
            assertThat(machine.coverage()).isEqualTo(1.0d);
            assertThat(machine.deadEndStates()).isEmpty();
            assertThat(machine.unreachableStates()).isEmpty();
        }

        @Test
        @DisplayName("RETIRED is the single terminal state")
        void retiredIsTerminal() {
            var machine = KeyRotationPolicy.lifecycle();
            assertThat(machine.isTerminal(SigningKeyState.RETIRED)).isTrue();
            assertThat(machine.isTerminal(SigningKeyState.PENDING)).isFalse();
            assertThat(machine.isTerminal(SigningKeyState.ACTIVE)).isFalse();
            assertThat(machine.isTerminal(SigningKeyState.RETIRING)).isFalse();
        }
    }

    @Nested
    @DisplayName("legal vs illegal transitions")
    class Transitions {

        @Test
        @DisplayName("only PENDING->ACTIVE->RETIRING->RETIRED is legal")
        void onlyForwardChainIsLegal() {
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.PENDING, SigningKeyState.ACTIVE))
                    .isTrue();
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.ACTIVE, SigningKeyState.RETIRING))
                    .isTrue();
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.RETIRING, SigningKeyState.RETIRED))
                    .isTrue();
        }

        @Test
        @DisplayName("skipping a state is illegal (no PENDING->RETIRING, no PENDING->RETIRED)")
        void skippingIsIllegal() {
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.PENDING, SigningKeyState.RETIRING))
                    .isFalse();
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.PENDING, SigningKeyState.RETIRED))
                    .isFalse();
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.ACTIVE, SigningKeyState.RETIRED))
                    .isFalse();
        }

        @Test
        @DisplayName("moving backwards is illegal and RETIRED is terminal")
        void backwardsAndTerminalAreIllegal() {
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.ACTIVE, SigningKeyState.PENDING))
                    .isFalse();
            assertThat(KeyRotationPolicy.isLegalTransition(
                            SigningKeyState.RETIRING, SigningKeyState.ACTIVE))
                    .isFalse();
            for (SigningKeyState to : SigningKeyState.values()) {
                assertThat(KeyRotationPolicy.isLegalTransition(SigningKeyState.RETIRED, to))
                        .as("RETIRED -> %s", to)
                        .isFalse();
            }
        }

        @Test
        @DisplayName("transition() applies a legal move and rejects an illegal one")
        void transitionApplyAndReject() {
            assertThat(KeyRotationPolicy.transition(
                            SigningKeyState.PENDING, SigningKeyState.ACTIVE))
                    .isEqualTo(SigningKeyState.ACTIVE);
            assertThatThrownBy(
                            () -> KeyRotationPolicy.transition(
                                    SigningKeyState.PENDING, SigningKeyState.RETIRED))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    @DisplayName("publish-before-sign")
    class PublishBeforeSign {

        @Test
        @DisplayName("only ACTIVE may sign; PENDING/RETIRING/RETIRED may not")
        void onlyActiveSigns() {
            assertThat(KeyRotationPolicy.canSign(SigningKeyState.ACTIVE)).isTrue();
            assertThat(KeyRotationPolicy.canSign(SigningKeyState.PENDING)).isFalse();
            assertThat(KeyRotationPolicy.canSign(SigningKeyState.RETIRING)).isFalse();
            assertThat(KeyRotationPolicy.canSign(SigningKeyState.RETIRED)).isFalse();
        }

        @Test
        @DisplayName("a key reaches ACTIVE only via PENDING — it was published first")
        void activeOnlyFromPending() {
            // The only transition whose target is ACTIVE starts at PENDING (published).
            for (SigningKeyState from : SigningKeyState.values()) {
                boolean legalToActive =
                        KeyRotationPolicy.isLegalTransition(from, SigningKeyState.ACTIVE);
                assertThat(legalToActive)
                        .as("%s -> ACTIVE", from)
                        .isEqualTo(from == SigningKeyState.PENDING);
            }
        }

        @Test
        @DisplayName("PENDING is publishable (pre-trust) but does not sign")
        void pendingIsPrePublished() {
            assertThat(KeyRotationPolicy.isPublishable(SigningKeyState.PENDING)).isTrue();
            assertThat(KeyRotationPolicy.canSign(SigningKeyState.PENDING)).isFalse();
            assertThat(KeyRotationPolicy.isPublishable(SigningKeyState.RETIRED)).isFalse();
        }
    }

    @Nested
    @DisplayName("retire-after-max-TTL (clock injected)")
    class RetireAfterTtl {

        @Test
        @DisplayName("ACTIVE key younger than the TTL is not due for retiring")
        void youngActiveNotDue() {
            SigningKeyDescriptor k = key("a", SigningKeyState.ACTIVE, T0);
            Instant now = T0.plus(Duration.ofHours(23));
            assertThat(KeyRotationPolicy.isDueForRetiring(k, MAX_TTL, now)).isFalse();
        }

        @Test
        @DisplayName("ACTIVE key past the TTL is due for retiring")
        void agedActiveIsDue() {
            SigningKeyDescriptor k = key("a", SigningKeyState.ACTIVE, T0);
            Instant now = T0.plus(MAX_TTL);
            assertThat(KeyRotationPolicy.isDueForRetiring(k, MAX_TTL, now)).isTrue();
        }

        @Test
        @DisplayName("a non-ACTIVE key is never due for retiring")
        void nonActiveNeverDueForRetiring() {
            SigningKeyDescriptor pending = key("p", SigningKeyState.PENDING, null);
            Instant now = T0.plus(Duration.ofDays(10));
            assertThat(KeyRotationPolicy.isDueForRetiring(pending, MAX_TTL, now)).isFalse();
        }

        @Test
        @DisplayName("RETIRING key past TTL+grace is due for retired; within window is not")
        void retiringWindow() {
            SigningKeyDescriptor k = key("r", SigningKeyState.RETIRING, T0);
            Instant withinGrace = T0.plus(MAX_TTL).plus(Duration.ofHours(11));
            Instant pastGrace = T0.plus(MAX_TTL).plus(GRACE);
            assertThat(KeyRotationPolicy.isDueForRetired(k, MAX_TTL, GRACE, withinGrace)).isFalse();
            assertThat(KeyRotationPolicy.isDueForRetired(k, MAX_TTL, GRACE, pastGrace)).isTrue();
        }
    }

    @Nested
    @DisplayName("JWKS publication and selection")
    class PublicationAndSelection {

        @Test
        @DisplayName("published JWKS contains PENDING, ACTIVE and RETIRING, never RETIRED")
        void jwksContainsPendingActiveAndRetiring() {
            List<SigningKeyDescriptor> keys = List.of(
                    key("pending", SigningKeyState.PENDING, null),
                    key("active", SigningKeyState.ACTIVE, T0),
                    key("retiring", SigningKeyState.RETIRING, T0.minus(MAX_TTL)),
                    key("retired", SigningKeyState.RETIRED, T0.minus(Duration.ofDays(2))));

            List<PublicJwk> published = KeyRotationPolicy.publishedJwks(keys);

            // PENDING is pre-published (publish-before-sign); only RETIRED is withdrawn.
            assertThat(published)
                    .extracting(j -> j.keyId().value())
                    .containsExactly("pending", "active", "retiring");
        }

        @Test
        @DisplayName("select picks a published key by kid + alg + use")
        void selectByKidAlgUse() {
            List<SigningKeyDescriptor> keys = List.of(
                    key("active", SigningKeyState.ACTIVE, T0),
                    key("retiring", SigningKeyState.RETIRING, T0.minus(MAX_TTL)));

            Optional<SigningKeyDescriptor> found = KeyRotationPolicy.select(
                    keys, KeyId.of("retiring"), SigningAlgorithm.EdDSA, KeyUse.SIGNATURE);

            assertThat(found).isPresent();
            assertThat(found.get().keyId().value()).isEqualTo("retiring");
        }

        @Test
        @DisplayName("select never returns a PENDING or RETIRED key, nor a wrong alg/use")
        void selectRejectsUnpublishedAndMismatches() {
            List<SigningKeyDescriptor> keys = List.of(
                    key("pending", SigningKeyState.PENDING, null),
                    key("active", SigningKeyState.ACTIVE, T0));

            assertThat(KeyRotationPolicy.select(
                            keys, KeyId.of("pending"), SigningAlgorithm.EdDSA, KeyUse.SIGNATURE))
                    .isEmpty();
            assertThat(KeyRotationPolicy.select(
                            keys, KeyId.of("active"), SigningAlgorithm.ES256, KeyUse.SIGNATURE))
                    .isEmpty();
            assertThat(KeyRotationPolicy.select(
                            keys, KeyId.of("active"), SigningAlgorithm.EdDSA, KeyUse.ENCRYPTION))
                    .isEmpty();
        }

        @Test
        @DisplayName("currentSigningKey returns the single ACTIVE key, empty if none")
        void currentSigningKeySingleActive() {
            List<SigningKeyDescriptor> keys = List.of(
                    key("active", SigningKeyState.ACTIVE, T0),
                    key("retiring", SigningKeyState.RETIRING, T0.minus(MAX_TTL)));
            assertThat(KeyRotationPolicy.currentSigningKey(keys))
                    .map(k -> k.keyId().value())
                    .contains("active");

            assertThat(KeyRotationPolicy.currentSigningKey(
                            List.of(key("retiring", SigningKeyState.RETIRING, T0))))
                    .isEmpty();
        }

        @Test
        @DisplayName("currentSigningKey rejects an ambiguous realm with two ACTIVE keys")
        void currentSigningKeyAmbiguous() {
            List<SigningKeyDescriptor> keys = List.of(
                    key("a1", SigningKeyState.ACTIVE, T0),
                    key("a2", SigningKeyState.ACTIVE, T0));
            assertThatThrownBy(() -> KeyRotationPolicy.currentSigningKey(keys))
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}
