package dev.tessera.iam.domain.authflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import dev.tessera.iam.domain.authflow.AuthEvent.ConsentDenied;
import dev.tessera.iam.domain.authflow.AuthEvent.ConsentGranted;
import dev.tessera.iam.domain.authflow.AuthEvent.IdentifierSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.MfaSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.PasswordSubmitted;
import dev.tessera.iam.domain.authflow.AuthEvent.StepCancelled;
import dev.tessera.iam.domain.authflow.AuthEvent.WebAuthnAssertionSubmitted;
import dev.tessera.iam.domain.authflow.AuthFlowReducer.ReduceResult;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AuthFlowReducer — the pure auth-flow engine")
class AuthFlowReducerTest {

    private static final long T0 = 1_700_000_000_000L;

    private final AuthFlowReducer reducer = new AuthFlowReducer();
    private final RealmKey realm = new RealmKey(TenantId.generate(), BaselineId.generate());
    private final Subject subject = new Subject("sub-123", realm);

    private AuthExchange exchange(AuthStep... steps) {
        return AuthExchange.start(realm, List.of(steps));
    }

    @Nested
    @DisplayName("dispatch completeness")
    class DispatchCompleteness {

        @Test
        @DisplayName("building the reducer verifies a handler for every AuthStep variant")
        void everyStepVariantHandled() {
            // The dispatch table is assembled with TypedStateMachineBuilder.buildStrict(),
            // which throws if any permitted AuthStep variant lacks a handler — the
            // build-time analog of an exhaustive switch.
            assertThatCode(AuthFlowReducer::new).doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("happy-path flows")
    class HappyPath {

        @Test
        @DisplayName("identifier → password → MFA reaches Authenticated with session + audit effects")
        void fullFlowReachesAuthenticated() {
            AuthExchange state = exchange(
                    new AuthStep.IdentifyUser(),
                    new AuthStep.VerifyPassword(3),
                    new AuthStep.RequireMfa(MfaKind.TOTP));

            ReduceResult r1 = reducer.reduce(state, new IdentifierSubmitted(subject, T0));
            assertThat(r1.outcome()).isInstanceOf(AuthOutcome.Continue.class);
            assertThat(r1.nextState().subject()).contains(subject);

            ReduceResult r2 = reducer.reduce(r1.nextState(), new PasswordSubmitted(true, T0));
            assertThat(r2.outcome()).isInstanceOf(AuthOutcome.Continue.class);

            ReduceResult r3 = reducer.reduce(r2.nextState(), new MfaSubmitted(MfaKind.TOTP, true, T0));
            assertThat(r3.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
            assertThat(((AuthOutcome.Authenticated) r3.outcome()).subject()).isEqualTo(subject);
            assertThat(r3.nextState().status()).isEqualTo(AuthExchange.Status.AUTHENTICATED);
            assertThat(r3.effects())
                    .hasAtLeastOneElementOfType(SideEffectRequest.PersistSession.class)
                    .hasAtLeastOneElementOfType(SideEffectRequest.RecordAuditEvent.class);
        }

        @Test
        @DisplayName("a single-step identify flow authenticates immediately")
        void singleStepFlow() {
            AuthExchange state = exchange(new AuthStep.IdentifyUser());
            ReduceResult r = reducer.reduce(state, new IdentifierSubmitted(subject, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
        }
    }

    @Nested
    @DisplayName("challenge-as-value paths (never thrown)")
    class Challenges {

        @Test
        @DisplayName("an MFA step with no answer returns Challenge, not an exception")
        void mfaRequiredReturnsChallenge() {
            AuthExchange state = exchange(new AuthStep.RequireMfa(MfaKind.WEBAUTHN))
                    .withSubject(subject);
            // drive a non-MFA event (StepCancelled would deny); use a mismatched MFA kind
            ReduceResult r = reducer.reduce(state, new MfaSubmitted(MfaKind.TOTP, true, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Challenge.class);
            AuthOutcome.Challenge challenge = (AuthOutcome.Challenge) r.outcome();
            assertThat(challenge.descriptor().kind())
                    .isEqualTo(ChallengeDescriptor.Kind.MFA_REQUIRED);
            assertThat(r.nextState().status()).isEqualTo(AuthExchange.Status.CHALLENGED);
        }

        @Test
        @DisplayName("a consent gate with no decision returns a CONSENT_REQUIRED challenge")
        void consentGateChallenges() {
            AuthExchange state = exchange(new AuthStep.ConsentGate("profile")).withSubject(subject);
            ReduceResult r = reducer.reduce(state, new IdentifierSubmitted(subject, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Challenge.class);
            assertThat(((AuthOutcome.Challenge) r.outcome()).descriptor().kind())
                    .isEqualTo(ChallengeDescriptor.Kind.CONSENT_REQUIRED);
        }

        @Test
        @DisplayName("granting consent advances the consent gate to Authenticated")
        void consentGrantedAdvances() {
            AuthExchange state = exchange(new AuthStep.ConsentGate("profile")).withSubject(subject);
            ReduceResult r = reducer.reduce(state, new ConsentGranted("profile", T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
        }

        @Test
        @DisplayName("WebAuthn assertion success records phishing-resistant acr and authenticates")
        void webAuthnSuccess() {
            AuthExchange state = exchange(new AuthStep.WebAuthnAssertion()).withSubject(subject);
            ReduceResult r = reducer.reduce(state, new WebAuthnAssertionSubmitted(true, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
            assertThat(r.nextState().fact("auth.acr")).contains("phishing-resistant");
        }
    }

    @Nested
    @DisplayName("denial paths")
    class Denials {

        @Test
        @DisplayName("an unknown identifier is denied with an audit effect")
        void unknownIdentifierDenied() {
            AuthExchange state = exchange(new AuthStep.IdentifyUser());
            ReduceResult r = reducer.reduce(state, new IdentifierSubmitted(null, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Denied.class);
            assertThat(r.effects()).hasAtLeastOneElementOfType(SideEffectRequest.RecordAuditEvent.class);
        }

        @Test
        @DisplayName("exhausted password attempts reach Denied with a brute-force effect")
        void exhaustedAttemptsDenied() {
            AuthExchange state = exchange(new AuthStep.VerifyPassword(2)).withSubject(subject);

            ReduceResult first = reducer.reduce(state, new PasswordSubmitted(false, T0));
            assertThat(first.outcome()).isInstanceOf(AuthOutcome.Challenge.class);
            assertThat(first.effects())
                    .hasAtLeastOneElementOfType(SideEffectRequest.IncrementBruteForceCounter.class);

            ReduceResult second = reducer.reduce(first.nextState(), new PasswordSubmitted(false, T0));
            assertThat(second.outcome()).isInstanceOf(AuthOutcome.Denied.class);
            assertThat(second.effects())
                    .hasAtLeastOneElementOfType(SideEffectRequest.IncrementBruteForceCounter.class)
                    .hasAtLeastOneElementOfType(SideEffectRequest.RecordAuditEvent.class);
        }

        @Test
        @DisplayName("refusing consent denies the flow")
        void consentDeniedDenies() {
            AuthExchange state = exchange(new AuthStep.ConsentGate("profile")).withSubject(subject);
            ReduceResult r = reducer.reduce(state, new ConsentDenied("profile", T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Denied.class);
        }

        @Test
        @DisplayName("cancelling any step denies the flow")
        void cancelDenies() {
            AuthExchange state = exchange(
                    new AuthStep.IdentifyUser(), new AuthStep.VerifyPassword(3));
            ReduceResult r = reducer.reduce(state, new StepCancelled(T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Denied.class);
        }
    }

    @Nested
    @DisplayName("conditional steps")
    class Conditionals {

        @Test
        @DisplayName("a conditional step is skipped when its required fact is absent")
        void conditionalSkippedWhenFactAbsent() {
            AuthExchange state = exchange(
                    new AuthStep.ConditionalStep("risk.high", new AuthStep.RequireMfa(MfaKind.TOTP)),
                    new AuthStep.IdentifyUser());
            // No 'risk.high' fact: the conditional is skipped and IdentifyUser runs.
            ReduceResult r = reducer.reduce(state.withSubject(subject), new IdentifierSubmitted(subject, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
        }

        @Test
        @DisplayName("a conditional step applies when its required fact is present")
        void conditionalAppliesWhenFactPresent() {
            AuthExchange state = exchange(
                    new AuthStep.ConditionalStep("risk.high", new AuthStep.RequireMfa(MfaKind.TOTP)))
                    .withSubject(subject)
                    .withFact("risk.high", "true");
            ReduceResult r = reducer.reduce(state, new MfaSubmitted(MfaKind.TOTP, true, T0));
            assertThat(r.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
        }
    }

    @Nested
    @DisplayName("purity")
    class Purity {

        @Test
        @DisplayName("reduce is deterministic: same inputs yield equal results")
        void deterministic() {
            AuthExchange state = exchange(
                    new AuthStep.IdentifyUser(), new AuthStep.VerifyPassword(3));
            IdentifierSubmitted event = new IdentifierSubmitted(subject, T0);

            ReduceResult a = reducer.reduce(state, event);
            ReduceResult b = reducer.reduce(state, event);

            assertThat(a).isEqualTo(b);
            assertThat(a.nextState()).isEqualTo(b.nextState());
            assertThat(a.effects()).isEqualTo(b.effects());
        }

        @Test
        @DisplayName("reduce never mutates the input exchange")
        void doesNotMutateInput() {
            AuthExchange state = exchange(
                    new AuthStep.IdentifyUser(), new AuthStep.VerifyPassword(3));
            int remainingBefore = state.remainingSteps().size();
            int completedBefore = state.completedSteps().size();
            AuthExchange.Status statusBefore = state.status();

            ReduceResult r = reducer.reduce(state, new IdentifierSubmitted(subject, T0));

            // input untouched; only the returned nextState moved forward
            assertThat(state.remainingSteps()).hasSize(remainingBefore);
            assertThat(state.completedSteps()).hasSize(completedBefore);
            assertThat(state.status()).isEqualTo(statusBefore);
            assertThat(state.subject()).isEmpty();
            assertThat(r.nextState()).isNotSameAs(state);
            assertThat(r.nextState().completedSteps()).hasSize(completedBefore + 1);
        }

        @Test
        @DisplayName("effects list is unmodifiable")
        void effectsUnmodifiable() {
            AuthExchange state = exchange(new AuthStep.IdentifyUser());
            ReduceResult r = reducer.reduce(state, new IdentifierSubmitted(subject, T0));
            org.assertj.core.api.Assertions.assertThatThrownBy(
                            () -> r.effects().add(
                                    new SideEffectRequest.IncrementBruteForceCounter(realm, subject)))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("a terminal exchange ignores further events idempotently")
        void terminalIsIdempotent() {
            AuthExchange state = exchange(new AuthStep.IdentifyUser());
            ReduceResult done = reducer.reduce(state, new IdentifierSubmitted(subject, T0));
            assertThat(done.nextState().status()).isEqualTo(AuthExchange.Status.AUTHENTICATED);

            ReduceResult again = reducer.reduce(done.nextState(), new PasswordSubmitted(true, T0));
            assertThat(again.outcome()).isInstanceOf(AuthOutcome.Authenticated.class);
            assertThat(again.effects()).isEmpty();
            assertThat(again.nextState()).isEqualTo(done.nextState());
        }
    }
}
