package dev.tessera.iam.domain.authflow;

/**
 * The second-factor families the auth flow can require
 *.
 *
 * <p>A small closed enum keeps {@link RequireMfa} and the MFA-related events
 * data-only, so the pure reducer can switch on the requested factor without
 * reaching into any credential adapter. {@link #WEBAUTHN} is the
 * phishing-resistant factor the design treats as first-class
 * (see {@link WebAuthnAssertion}); the design's {@code acr}/{@code amr} truthfulness
 * rule (threat #17) means a flow may only assert it once the matching factor has
 * actually completed.
 */
public enum MfaKind {

    /** RFC 6238 time-based one-time password. */
    TOTP,

    /** A phishing-resistant WebAuthn / passkey assertion. */
    WEBAUTHN,

    /** A pre-issued single-use recovery code. */
    RECOVERY_CODE
}
