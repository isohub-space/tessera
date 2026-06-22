package dev.tessera.iam.domain.authflow;

/**
 * A data description of what a client is being challenged for, carried by
 * {@link AuthOutcome.Challenge}.
 *
 * <p>Keeping the "what" of a challenge as an enum plus an opaque detail string lets
 * the pure reducer emit a fully self-describing challenge without constructing any
 * adapter-specific prompt (no WebAuthn options blob, no rendered form). The shell
 * maps a {@code ChallengeDescriptor} onto whatever wire representation the protocol
 * needs.
 *
 * @param kind   the category of challenge (never {@code null})
 * @param detail an audit/diagnostic detail (e.g. the scope or factor); may be empty
 *               but never {@code null}
 */
public record ChallengeDescriptor(Kind kind, String detail) {

    /** The categories of challenge the flow can raise. */
    public enum Kind {
        /** A second factor of some {@link MfaKind} is required. */
        MFA_REQUIRED,
        /** A WebAuthn / passkey assertion is required. */
        WEBAUTHN_REQUIRED,
        /** The user must grant consent for a scope. */
        CONSENT_REQUIRED,
        /** A fresh re-authentication (step-up) is required. */
        STEP_UP_REQUIRED
    }

    public ChallengeDescriptor {
        if (kind == null) {
            throw new IllegalArgumentException("ChallengeDescriptor kind must not be null");
        }
        if (detail == null) {
            throw new IllegalArgumentException("ChallengeDescriptor detail must not be null (use empty string)");
        }
    }

    /** A challenge for a second factor of the given kind. */
    public static ChallengeDescriptor mfa(MfaKind mfaKind) {
        return new ChallengeDescriptor(Kind.MFA_REQUIRED, mfaKind.name());
    }

    /** A challenge for a WebAuthn assertion. */
    public static ChallengeDescriptor webAuthn() {
        return new ChallengeDescriptor(Kind.WEBAUTHN_REQUIRED, "");
    }

    /** A challenge to grant consent for the given scope. */
    public static ChallengeDescriptor consent(String scope) {
        return new ChallengeDescriptor(Kind.CONSENT_REQUIRED, scope);
    }

    /** A challenge to re-authenticate (step-up) for the given reason. */
    public static ChallengeDescriptor stepUp(String reason) {
        return new ChallengeDescriptor(Kind.STEP_UP_REQUIRED, reason);
    }
}
