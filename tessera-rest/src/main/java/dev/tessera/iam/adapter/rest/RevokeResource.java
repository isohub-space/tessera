package dev.tessera.iam.adapter.rest;

import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeCommand;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeResult;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The token-revocation endpoint ({@code POST /revoke}, RFC 7009).
 *
 * <p>A thin shell over {@link RevokeUseCase}: it parses the form-encoded request, supports the
 * client presenting its secret via the body ({@code client_secret}) or HTTP Basic, and renders the
 * use case's outcome:
 * <ul>
 *   <li><strong>success</strong>: a {@code 200} with an <em>empty</em> body (RFC 7009 §2.2),
 *       regardless of whether the token was live, already revoked, unknown, malformed, or belongs
 *       to another tenant — the endpoint is a non-oracle;</li>
 *   <li><strong>client-authentication failure</strong>: a {@code 401} {@code invalid_client}.</li>
 * </ul>
 * Both responses carry the {@code no-store} cache headers. This is the only endpoint outcome a
 * caller can observe, so a token it does not own is indistinguishable from one it does.
 */
@Path("/revoke")
@Tag(name = "revocation", description = "OAuth 2.0 token revocation endpoint (RFC 7009).")
@TenantScoped
@RateLimited
public class RevokeResource {

    @Inject
    RevokeUseCase revoke;

    @Inject
    TenantContext tenantContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            operationId = "revoke",
            summary = "Revoke a refresh token (RFC 7009); always 200 unless client auth fails")
    public Uni<Response> revoke(
            @HeaderParam("Authorization") String authorization,
            @FormParam("token") String token,
            @FormParam("token_type_hint") String tokenTypeHint,
            @FormParam("client_id") String clientId,
            @FormParam("client_secret") String clientSecret) {

        RealmKey realm = tenantContext.realm();

        // HTTP Basic client authentication takes precedence over body params (RFC 6749 §2.3.1),
        // exactly as at the token endpoint.
        BasicCredentials basic = BasicCredentials.parse(authorization);
        String resolvedClientId = basic != null ? basic.clientId() : clientId;
        String resolvedSecret = basic != null ? basic.clientSecret() : clientSecret;

        if (isBlank(resolvedClientId)) {
            // No identifiable client to authenticate — an invalid_client failure.
            return Uni.createFrom().item(unauthorizedClient());
        }

        RevokeCommand command =
                new RevokeCommand(realm, token, tokenTypeHint, resolvedClientId, resolvedSecret);
        return revoke.revoke(command).map(RevokeResource::render);
    }

    private static Response render(RevokeResult result) {
        return switch (result) {
            case RevokeResult.Done ignored -> success();
            case RevokeResult.ClientAuthenticationFailed ignored -> unauthorizedClient();
        };
    }

    /** RFC 7009 §2.2: a successful revocation is a {@code 200} with an empty body. */
    private static Response success() {
        return Response.ok()
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private static Response unauthorizedClient() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity(new OAuthErrorDto(
                        AuthorizationError.INVALID_CLIENT.code(), "client authentication failed"))
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
