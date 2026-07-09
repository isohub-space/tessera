package dev.tessera.iam.adapter.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * A token-introspection response (RFC 7662 §2.2).
 *
 * <p>{@code active} is the only always-present member. For an inactive token the response is exactly
 * {@code {"active": false}} — every other member is {@code null} and omitted ({@code NON_NULL}), so
 * an inactive result reveals nothing (RFC 7662's non-oracle requirement). For an active token the
 * server echoes the members it can supply; a member the token does not carry (e.g. a refresh token
 * has no {@code scope}, {@code jti}, or {@code token_type}) is likewise omitted.
 *
 * @param active    whether the token is currently active
 * @param scope     space-delimited scopes, or {@code null}
 * @param clientId  the client the token was issued to, or {@code null}
 * @param subject   the token's subject, or {@code null}
 * @param tokenType the token type ({@code Bearer} for an access token), or {@code null}
 * @param exp       expiry in seconds since the epoch, or {@code null}
 * @param iat       issuance in seconds since the epoch, or {@code null}
 * @param jti       token identifier, or {@code null}
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "IntrospectionResponse", description = "An RFC 7662 token-introspection response.")
public record IntrospectionResponseDto(
        @JsonProperty("active") boolean active,
        @JsonProperty("scope") String scope,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("sub") String subject,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("exp") Long exp,
        @JsonProperty("iat") Long iat,
        @JsonProperty("jti") String jti) {

    /** The canonical inactive response — {@code {"active": false}} and nothing else. */
    public static final IntrospectionResponseDto INACTIVE =
            new IntrospectionResponseDto(false, null, null, null, null, null, null, null);
}
