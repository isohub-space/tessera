package dev.tessera.iam.adapter.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * An OAuth 2.0 error response body (RFC 6749 §5.2), served as JSON from the token
 * endpoint (and as the body of a non-redirectable authorization error).
 *
 * <p>The {@code error} is one of the registered codes; the {@code error_description} is a
 * non-sensitive, human-readable explanation. It must never echo a secret, a PKCE verifier,
 * or whether a code existed — the domain collapses indistinguishable failures to
 * {@code invalid_grant} precisely so a client cannot probe which check failed.
 *
 * @param error            the RFC 6749 error code (e.g. {@code invalid_grant})
 * @param errorDescription a non-sensitive human-readable description
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "OAuthError", description = "An OAuth 2.0 error response (RFC 6749 §5.2).")
public record OAuthErrorDto(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription) {
}
