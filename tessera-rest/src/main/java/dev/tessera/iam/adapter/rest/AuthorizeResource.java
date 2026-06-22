package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The authorization endpoint ({@code GET /authorize}) of the Authorization Code + PKCE
 * flow (RFC 6749 §4.1.1, OIDC Core §3.1.2).
 *
 * <p>This adapter is a thin shell over {@link AuthorizeUseCase}: it parses and structurally
 * validates the query parameters into an {@link AuthorizationRequest} (which makes PKCE
 * mandatory and {@code S256}-only by construction), supplies the authenticated end-user's
 * {@code sub}, and renders the use case's outcome as the protocol response —
 *
 * <ul>
 *   <li><strong>success</strong>: a {@code 302} redirect to the registered
 *       {@code redirect_uri} carrying {@code code}, the round-tripped {@code state}, and the
 *       RFC 9207 {@code iss} (so a client can detect a mix-up attack);</li>
 *   <li><strong>redirectable error</strong>: a {@code 302} redirect carrying {@code error},
 *       {@code error_description}, {@code state} and {@code iss} (RFC 6749 §4.1.2.1);</li>
 *   <li><strong>non-redirectable error</strong> (unknown client / unregistered redirect URI
 *       — the redirect target is itself untrusted): a {@code 400} with the error in the body,
 *       <em>never</em> redirected to an unvalidated URI.</li>
 * </ul>
 *
 * <h2>End-user authentication seam</h2>
 * In a complete server the {@code sub} comes from an authenticated session established by a
 * login/consent step. That UI is not part of this flow; the authenticated subject is taken
 * from the {@code X-Subject-Id} header, which is where the login/consent front-end (or an
 * upstream authenticating proxy) injects the established identity. A request with no subject
 * is refused ({@code login_required} is out of scope here — it is an {@code access_denied}).
 */
@Path("/authorize")
@Tag(name = "authorization", description = "OAuth 2.0 / OIDC authorization endpoint.")
public class AuthorizeResource {

    /** The only response type this server supports (RFC 6749 §3.1.1). */
    private static final String RESPONSE_TYPE_CODE = "code";

    /** The only PKCE challenge method this server honours (RFC 7636 §4.3). */
    private static final String CHALLENGE_METHOD_S256 = "S256";

    @Inject
    AuthorizeUseCase authorize;

    @Inject
    OidcDiscoveryConfig config;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            operationId = "authorize",
            summary = "Authorize a request and issue a single-use code (Authorization Code + PKCE)")
    public Uni<Response> authorize(
            @HeaderParam("X-Tenant-Id") String tenantHeader,
            @HeaderParam("X-Baseline-Id") String baselineHeader,
            @HeaderParam("X-Subject-Id") String subjectId,
            @QueryParam("response_type") String responseType,
            @QueryParam("client_id") String clientId,
            @QueryParam("redirect_uri") String redirectUri,
            @QueryParam("scope") String scope,
            @QueryParam("state") String state,
            @QueryParam("nonce") String nonce,
            @QueryParam("code_challenge") String codeChallenge,
            @QueryParam("code_challenge_method") String codeChallengeMethod) {

        RealmKey realm = RealmHeaders.resolve(tenantHeader, baselineHeader);

        // Authorization-time validation errors are deliberately NOT redirected. RFC 6749
        // §4.1.2.1: an error may be delivered to a redirect_uri only once that URI has been
        // verified as registered to the client. This server does not yet have a registered-
        // redirect-URI check at /authorize (the Client model carries no registered URIs — a
        // client-registration concern), so to avoid acting as an open redirector EVERY
        // authorize-time error is returned as a 400 to the user agent, never redirected.
        // Only the success path delivers to the requested redirect_uri; the issued code is
        // additionally bound to that exact URI and to the PKCE challenge, so the token
        // endpoint re-checks both before any token is minted.
        if (isBlank(clientId) || isBlank(redirectUri)) {
            return badRequest(AuthorizationError.INVALID_REQUEST,
                    "client_id and redirect_uri are required");
        }
        if (!RESPONSE_TYPE_CODE.equals(responseType)) {
            return badRequest(AuthorizationError.UNSUPPORTED_RESPONSE_TYPE,
                    "only response_type=code is supported");
        }
        if (isBlank(state)) {
            return badRequest(AuthorizationError.INVALID_REQUEST, "state is required");
        }
        if (isBlank(nonce)) {
            return badRequest(AuthorizationError.INVALID_REQUEST, "nonce is required");
        }
        // PKCE is mandatory and S256-only — a missing or non-S256 challenge is refused here,
        // mirroring the domain's compile-time guarantee (CodeChallenge / PkceMethod).
        if (isBlank(codeChallenge)) {
            return badRequest(AuthorizationError.INVALID_REQUEST,
                    "code_challenge is required (PKCE S256 is mandatory)");
        }
        if (codeChallengeMethod != null && !CHALLENGE_METHOD_S256.equals(codeChallengeMethod)) {
            return badRequest(AuthorizationError.INVALID_REQUEST,
                    "code_challenge_method must be S256");
        }
        if (isBlank(subjectId)) {
            // No authenticated end-user — in a full flow this is where login/consent runs.
            return badRequest(AuthorizationError.ACCESS_DENIED, "no authenticated subject");
        }

        AuthorizationRequest request;
        try {
            request = new AuthorizationRequest(
                    realm,
                    clientId,
                    redirectUri,
                    parseScopes(scope),
                    state,
                    nonce,
                    CodeChallenge.s256(codeChallenge));
        } catch (IllegalArgumentException ex) {
            // A malformed challenge (wrong length / alphabet) or other structural problem.
            return badRequest(AuthorizationError.INVALID_REQUEST, ex.getMessage());
        }

        return authorize.authorize(request, subjectId)
                .map(result -> render(result, redirectUri, state));
    }

    private Response render(AuthorizeResult result, String redirectUri, String state) {
        return switch (result) {
            case AuthorizeResult.Issued issued -> redirect(
                    successRedirect(redirectUri, issued.code(), issued.state()));
            case AuthorizeResult.Failed failed -> failed.redirectable()
                    ? redirect(errorRedirect(redirectUri, failed.error(), failed.description(), state))
                    : errorBody(failed.error(), failed.description());
        };
    }

    /** A 302 redirect (RFC 6749 uses 302; the authorization response is delivered in the URI). */
    private static Response redirect(URI location) {
        return Response.status(Response.Status.FOUND).location(location).build();
    }

    // ------------------------------------------------------------- redirect builders

    /** Success redirect: {@code code}, {@code state} and the RFC 9207 {@code iss}. */
    private URI successRedirect(String redirectUri, String code, String state) {
        StringBuilder query = new StringBuilder()
                .append("code=").append(encode(code))
                .append("&state=").append(encode(state))
                .append("&iss=").append(encode(config.issuer()));
        return appendQuery(redirectUri, query.toString());
    }

    /** Error redirect: {@code error}, {@code error_description}, {@code state}, {@code iss}. */
    private URI errorRedirect(
            String redirectUri, AuthorizationError error, String description, String state) {
        StringBuilder query = new StringBuilder()
                .append("error=").append(encode(error.code()))
                .append("&error_description=").append(encode(description))
                .append("&iss=").append(encode(config.issuer()));
        if (!isBlank(state)) {
            query.append("&state=").append(encode(state));
        }
        return appendQuery(redirectUri, query.toString());
    }

    private static Uni<Response> badRequest(AuthorizationError error, String description) {
        return Uni.createFrom().item(errorBody(error, description));
    }

    private static Response errorBody(AuthorizationError error, String description) {
        return Response.status(Response.Status.BAD_REQUEST)
                .type(MediaType.APPLICATION_JSON)
                .entity(new OAuthErrorDto(error.code(), description))
                .build();
    }

    /** Appends a query string to a redirect URI, preserving any query it already carries. */
    private static URI appendQuery(String redirectUri, String query) {
        String separator = redirectUri.indexOf('?') >= 0 ? "&" : "?";
        return URI.create(redirectUri + separator + query);
    }

    private static Set<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
