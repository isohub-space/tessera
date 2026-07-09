package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.dto.TokenResponseDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase.RefreshCommand;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenRequestCommand;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.tenancy.RealmKey;
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
 * The token endpoint ({@code POST /token}) of the Authorization Code + PKCE flow
 * ({@code grant_type=authorization_code}, RFC 6749 §4.1.3).
 *
 * <p>A thin shell over {@link TokenUseCase}: it parses the form-encoded request, supports
 * the client presenting its secret via the body ({@code client_secret}) or HTTP Basic, and
 * renders the use case's outcome:
 * <ul>
 *   <li><strong>success</strong>: a {@code 200} {@link TokenResponseDto} with the signed
 *       RFC 9068 access token (and the ID token for an OIDC request), with the no-store
 *       cache headers RFC 6749 §5.1 requires;</li>
 *   <li><strong>failure</strong>: an RFC 6749 §5.2 error body. An {@code invalid_client}
 *       maps to {@code 401}; every other error to {@code 400}.</li>
 * </ul>
 *
 * <p>The endpoint deliberately learns nothing about <em>which</em> security check failed —
 * the use case collapses indistinguishable failures to {@code invalid_grant} (replayed or
 * unknown code, expired code, redirect-URI mismatch, PKCE mismatch) so a client cannot probe
 * the difference. The reactive fold keeps the (off-loop) Argon2id verify and JWS signing off
 * the event loop; this adapter only maps the result.
 */
@Path("/token")
@Tag(name = "token", description = "OAuth 2.0 / OIDC token endpoint.")
@TenantScoped
@RateLimited
public class TokenResource {

    private static final String GRANT_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_REFRESH_TOKEN = "refresh_token";

    @Inject
    TokenUseCase token;

    @Inject
    RefreshUseCase refresh;

    @Inject
    TenantContext tenantContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            operationId = "token",
            summary = "Redeem an authorization code for tokens (Authorization Code + PKCE)")
    public Uni<Response> token(
            @HeaderParam("Authorization") String authorization,
            @FormParam("grant_type") String grantType,
            @FormParam("code") String code,
            @FormParam("redirect_uri") String redirectUri,
            @FormParam("client_id") String clientId,
            @FormParam("client_secret") String clientSecret,
            @FormParam("code_verifier") String codeVerifier,
            @FormParam("refresh_token") String refreshToken,
            @FormParam("scope") String scope) {

        RealmKey realm = tenantContext.realm();

        // HTTP Basic client authentication takes precedence over body params (RFC 6749
        // §2.3.1 recommends Basic). A confidential client may present its credential either
        // way; a public client presents neither and relies on PKCE (or refresh possession).
        BasicCredentials basic = BasicCredentials.parse(authorization);
        String resolvedClientId = basic != null ? basic.clientId() : clientId;
        String resolvedSecret = basic != null ? basic.clientSecret() : clientSecret;

        if (GRANT_AUTHORIZATION_CODE.equals(grantType)) {
            if (isBlank(resolvedClientId) || isBlank(code) || isBlank(redirectUri)
                    || isBlank(codeVerifier)) {
                return error(Response.Status.BAD_REQUEST, AuthorizationError.INVALID_REQUEST,
                        "code, redirect_uri, client_id and code_verifier are required");
            }
            TokenRequestCommand command = new TokenRequestCommand(
                    realm, code, redirectUri, resolvedClientId, resolvedSecret, codeVerifier);
            return token.redeemAuthorizationCode(command).map(TokenResource::render);
        }

        if (GRANT_REFRESH_TOKEN.equals(grantType)) {
            if (isBlank(resolvedClientId) || isBlank(refreshToken)) {
                return error(Response.Status.BAD_REQUEST, AuthorizationError.INVALID_REQUEST,
                        "refresh_token and client_id are required");
            }
            RefreshCommand command = new RefreshCommand(
                    realm, refreshToken, resolvedClientId, resolvedSecret, scope);
            return refresh.redeem(command).map(TokenResource::render);
        }

        return error(Response.Status.BAD_REQUEST,
                AuthorizationError.UNSUPPORTED_GRANT_TYPE,
                "only grant_type=authorization_code and grant_type=refresh_token are supported");
    }

    private static Response render(TokenResult result) {
        return switch (result) {
            case TokenResult.Issued issued -> success(issued);
            case TokenResult.Failed failed -> {
                Response.Status status = failed.error() == AuthorizationError.INVALID_CLIENT
                        ? Response.Status.UNAUTHORIZED
                        : Response.Status.BAD_REQUEST;
                yield errorBody(status, failed.error(), failed.description());
            }
        };
    }

    private static Response success(TokenResult.Issued issued) {
        TokenResponseDto body = new TokenResponseDto(
                issued.accessToken(),
                TokenResponseDto.BEARER,
                issued.expiresInSecs(),
                issued.scope(),
                issued.idToken(),
                issued.refreshToken());
        // RFC 6749 §5.1: token responses must not be cached.
        return Response.ok(body)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private static Uni<Response> error(
            Response.Status status, AuthorizationError error, String description) {
        return Uni.createFrom().item(errorBody(status, error, description));
    }

    private static Response errorBody(
            Response.Status status, AuthorizationError error, String description) {
        return Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(new OAuthErrorDto(error.code(), description))
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .build();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
