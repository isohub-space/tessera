package dev.tessera.iam.adapter.rest;

import dev.tessera.iam.adapter.rest.dto.IntrospectionResponseDto;
import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.in.IntrospectUseCase.ActiveToken;
import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectCommand;
import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectionResult;
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
 * The token-introspection endpoint ({@code POST /introspect}, RFC 7662).
 *
 * <p>A thin shell over {@link IntrospectUseCase}: it parses the form-encoded request, authenticates
 * the caller (HTTP Basic or body credentials, same resolution as {@code /token} and {@code /revoke}),
 * and renders the outcome:
 * <ul>
 *   <li><strong>active</strong>: {@code 200} with an {@link IntrospectionResponseDto} carrying the
 *       echoable claims;</li>
 *   <li><strong>inactive / unknown / malformed / foreign-tenant</strong>: {@code 200} with exactly
 *       {@code {"active": false}} — the non-oracle response;</li>
 *   <li><strong>client-authentication failure</strong>: {@code 401} {@code invalid_client}.</li>
 * </ul>
 * All responses carry the {@code no-store} cache headers.
 */
@Path("/introspect")
@Tag(name = "introspection", description = "OAuth 2.0 token introspection endpoint (RFC 7662).")
@TenantScoped
@RateLimited
public class IntrospectResource {

    @Inject
    IntrospectUseCase introspect;

    @Inject
    TenantContext tenantContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            operationId = "introspect",
            summary = "Introspect a token's active state and claims (RFC 7662)")
    public Uni<Response> introspect(
            @HeaderParam("Authorization") String authorization,
            @FormParam("token") String token,
            @FormParam("token_type_hint") String tokenTypeHint,
            @FormParam("client_id") String clientId,
            @FormParam("client_secret") String clientSecret) {

        RealmKey realm = tenantContext.realm();

        BasicCredentials basic = BasicCredentials.parse(authorization);
        String resolvedClientId = basic != null ? basic.clientId() : clientId;
        String resolvedSecret = basic != null ? basic.clientSecret() : clientSecret;

        if (isBlank(resolvedClientId)) {
            // No identifiable caller to authenticate — an invalid_client failure.
            return Uni.createFrom().item(unauthorizedClient());
        }

        IntrospectCommand command =
                new IntrospectCommand(realm, token, tokenTypeHint, resolvedClientId, resolvedSecret);
        return introspect.introspect(command).map(IntrospectResource::render);
    }

    private static Response render(IntrospectionResult result) {
        return switch (result) {
            case IntrospectionResult.Active active -> ok(activeBody(active.token()));
            case IntrospectionResult.Inactive ignored -> ok(IntrospectionResponseDto.INACTIVE);
            case IntrospectionResult.ClientAuthenticationFailed ignored -> unauthorizedClient();
        };
    }

    private static IntrospectionResponseDto activeBody(ActiveToken token) {
        return new IntrospectionResponseDto(
                true,
                token.scope(),
                token.clientId(),
                token.subject(),
                token.tokenType(),
                token.exp(),
                token.iat(),
                token.jti());
    }

    private static Response ok(IntrospectionResponseDto body) {
        return Response.ok(body)
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
