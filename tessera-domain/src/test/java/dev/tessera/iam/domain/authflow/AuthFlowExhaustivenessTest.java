package dev.tessera.iam.domain.authflow;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Guards that the sealed hierarchies driving the flow are switched exhaustively with
 * <strong>no {@code default} branch</strong>. Each {@code switch} below is compiled,
 * so adding a new sealed member would break compilation here — exactly the
 * compile-time-exhaustiveness guarantee the design relies on.
 */
@DisplayName("Auth-flow sealed hierarchies — exhaustive switch, no default")
class AuthFlowExhaustivenessTest {

    private final RealmKey realm = new RealmKey(TenantId.generate(), BaselineId.generate());
    private final Subject subject = new Subject("sub-x", realm);

    @Test
    @DisplayName("AuthStep is matched exhaustively")
    void authStepExhaustive() {
        for (AuthStep step : new AuthStep[] {
                new AuthStep.IdentifyUser(),
                new AuthStep.VerifyPassword(3),
                new AuthStep.RequireMfa(MfaKind.TOTP),
                new AuthStep.WebAuthnAssertion(),
                new AuthStep.ConsentGate("profile"),
                new AuthStep.StepUp("danger"),
                new AuthStep.ConditionalStep("k", new AuthStep.IdentifyUser())
        }) {
            assertThat(label(step)).isNotBlank();
        }
    }

    private static String label(AuthStep step) {
        return switch (step) {
            case AuthStep.IdentifyUser ignored -> "identify";
            case AuthStep.VerifyPassword ignored -> "password";
            case AuthStep.RequireMfa ignored -> "mfa";
            case AuthStep.WebAuthnAssertion ignored -> "webauthn";
            case AuthStep.ConsentGate ignored -> "consent";
            case AuthStep.StepUp ignored -> "stepup";
            case AuthStep.ConditionalStep ignored -> "conditional";
        };
    }

    @Test
    @DisplayName("AuthOutcome is matched exhaustively")
    void authOutcomeExhaustive() {
        for (AuthOutcome outcome : new AuthOutcome[] {
                new AuthOutcome.Continue(new AuthStep.IdentifyUser()),
                new AuthOutcome.Challenge(new AuthStep.WebAuthnAssertion(), ChallengeDescriptor.webAuthn()),
                new AuthOutcome.Authenticated(subject),
                new AuthOutcome.Denied("nope")
        }) {
            String label = switch (outcome) {
                case AuthOutcome.Continue ignored -> "continue";
                case AuthOutcome.Challenge ignored -> "challenge";
                case AuthOutcome.Authenticated ignored -> "authenticated";
                case AuthOutcome.Denied ignored -> "denied";
            };
            assertThat(label).isNotBlank();
        }
    }

    @Test
    @DisplayName("AuthEvent is matched exhaustively")
    void authEventExhaustive() {
        for (AuthEvent event : new AuthEvent[] {
                new AuthEvent.IdentifierSubmitted(subject, 1L),
                new AuthEvent.PasswordSubmitted(true, 1L),
                new AuthEvent.MfaSubmitted(MfaKind.TOTP, true, 1L),
                new AuthEvent.WebAuthnAssertionSubmitted(true, 1L),
                new AuthEvent.ConsentGranted("profile", 1L),
                new AuthEvent.ConsentDenied("profile", 1L),
                new AuthEvent.StepCancelled(1L)
        }) {
            String label = switch (event) {
                case AuthEvent.IdentifierSubmitted ignored -> "id";
                case AuthEvent.PasswordSubmitted ignored -> "pw";
                case AuthEvent.MfaSubmitted ignored -> "mfa";
                case AuthEvent.WebAuthnAssertionSubmitted ignored -> "webauthn";
                case AuthEvent.ConsentGranted ignored -> "consent-grant";
                case AuthEvent.ConsentDenied ignored -> "consent-deny";
                case AuthEvent.StepCancelled ignored -> "cancel";
            };
            assertThat(label).isNotBlank();
        }
    }

    @Test
    @DisplayName("SideEffectRequest is matched exhaustively")
    void sideEffectExhaustive() {
        for (SideEffectRequest effect : new SideEffectRequest[] {
                new SideEffectRequest.SendVerificationEmail(realm, subject),
                new SideEffectRequest.PersistSession(realm, subject, 1L),
                new SideEffectRequest.RecordAuditEvent(realm, "T", "d", 1L),
                new SideEffectRequest.IncrementBruteForceCounter(realm, subject)
        }) {
            String label = switch (effect) {
                case SideEffectRequest.SendVerificationEmail ignored -> "email";
                case SideEffectRequest.PersistSession ignored -> "session";
                case SideEffectRequest.RecordAuditEvent ignored -> "audit";
                case SideEffectRequest.IncrementBruteForceCounter ignored -> "brute";
            };
            assertThat(label).isNotBlank();
        }
    }
}
