package dev.tessera.iam.domain.authcode;

/**
 * The OAuth 2.0 error codes this server returns from the authorization and token
 * endpoints (RFC 6749 §4.1.2.1 and §5.2).
 *
 * <p>A closed enum of the exact wire {@code error} tokens — so an endpoint can never
 * emit an off-spec error string, and every error path maps to a known HTTP status and
 * a known {@code error} code. The human-readable {@code error_description} is supplied
 * per-occurrence by the caller; it is never security-sensitive (it must not echo a
 * verifier, secret, or whether a code existed).
 */
public enum AuthorizationError {

    /** The request is missing a parameter, malformed, or otherwise invalid. */
    INVALID_REQUEST("invalid_request"),

    /** The client failed authentication at the token endpoint. */
    INVALID_CLIENT("invalid_client"),

    /**
     * The authorization code (grant) is invalid, expired, revoked, already used, or was
     * issued to another client / redirect URI, or the PKCE verifier did not match. RFC
     * 6749 deliberately collapses all of these into one code so a client cannot probe
     * which specific check failed.
     */
    INVALID_GRANT("invalid_grant"),

    /** The client is not authorised to use this grant/response type. */
    UNAUTHORIZED_CLIENT("unauthorized_client"),

    /** The {@code response_type} is not {@code code} (the only one this server offers). */
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),

    /** The {@code grant_type} is not {@code authorization_code} on the token endpoint. */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),

    /** The requested scope is unknown or exceeds what the client may request. */
    INVALID_SCOPE("invalid_scope"),

    /** The resource owner (or server policy) denied the request. */
    ACCESS_DENIED("access_denied"),

    /** An unexpected server-side condition prevented fulfilling the request. */
    SERVER_ERROR("server_error");

    private final String code;

    AuthorizationError(String code) {
        this.code = code;
    }

    /** The wire {@code error} token (RFC 6749). */
    public String code() {
        return code;
    }
}
