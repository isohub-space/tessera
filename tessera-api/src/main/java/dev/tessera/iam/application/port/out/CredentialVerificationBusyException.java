package dev.tessera.iam.application.port.out;

/**
 * A credential verifier refused to start a verification because it is saturated: too many
 * verifications are already running or waiting, overall or for the request's tenant, or the request
 * waited past its deadline. It depends only on load, never on the client or the credential, so it
 * reveals nothing about either. The edge answers it with {@code 503} and {@code Retry-After}.
 */
public final class CredentialVerificationBusyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long retryAfterSeconds;

    /** @param retryAfterSeconds when the caller should retry, in whole seconds (at least 1) */
    public CredentialVerificationBusyException(long retryAfterSeconds) {
        super("credential verification is saturated; retry after " + Math.max(1, retryAfterSeconds) + " s", null,
                false, false);
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    /** @return when the caller should retry, in whole seconds (at least 1) */
    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
