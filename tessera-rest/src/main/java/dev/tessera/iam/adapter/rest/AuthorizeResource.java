package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.tenancy.SubjectHeaders;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.application.port.in.SignInUseCase;
import dev.tessera.iam.application.port.in.SignInUseCase.BeginResult;
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
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
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
 * The authenticated subject is taken from the {@code X-Subject-Id} header, which
 * {@code SessionCookieFilter} fills from a session cookie (or a trusted upstream proxy
 * asserts). A request with no subject is handed to the hosted sign-in page: the client and
 * redirect URI are validated first, and only a request that could be answered is parked and
 * answered with {@code 303} to {@code /signin?txn=…} plus the cookie that binds it to this
 * browser ({@link SignInCookies}). A request that fails validation is a {@code 400} here, as
 * it would be for a signed-in user.
 *
 * <p><strong>See {@link SubjectHeaders} for this header's trust boundary</strong> — it must
 * never be trusted unless the deployment's edge strips any client-supplied value, exactly
 * like {@code X-Tenant-Id}. There is no code-level way to distinguish a genuine value from a
 * forged one once it reaches this method.
 */
@Path("/authorize")
@Tag(name = "authorization", description = "OAuth 2.0 / OIDC authorization endpoint.")
@TenantScoped
@RateLimited
public class AuthorizeResource {

    /** The only response type this server supports (RFC 6749 §3.1.1). */
    private static final String RESPONSE_TYPE_CODE = "code";

    /** The only PKCE challenge method this server honours (RFC 7636 §4.3). */
    private static final String CHALLENGE_METHOD_S256 = "S256";

    @Inject
    AuthorizeUseCase authorize;

    @Inject
    SignInUseCase signIn;

    @Inject
    OidcDiscoveryConfig config;

    @Inject
    TenantContext tenantContext;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            operationId = "authorize",
            summary = "Authorize a request and issue a single-use code (Authorization Code + PKCE)")
    public Uni<Response> authorize(
            @Context UriInfo uriInfo,
            @HeaderParam(SubjectHeaders.SUBJECT) String subjectId,
            @QueryParam("response_type") String responseType,
            @QueryParam("client_id") String clientId,
            @QueryParam("redirect_uri") String redirectUri,
            @QueryParam("scope") String scope,
            @QueryParam("state") String state,
            @QueryParam("nonce") String nonce,
            @QueryParam("code_challenge") String codeChallenge,
            @QueryParam("code_challenge_method") String codeChallengeMethod) {

        RealmKey realm = tenantContext.realm();

        // Authorization-time validation errors are deliberately NOT redirected. RFC 6749
        // §4.1.2.1: an error may be delivered to a redirect_uri only once that URI is verified
        // as registered to the client. The use case now validates the requested redirect_uri
        // against the client's registered allow-list (exact match) before issuing a code — an
        // unregistered URI is a non-redirectable 400 — but to stay strictly on the safe side
        // EVERY authorize-time error here is still returned as a 400 to the user agent rather
        // than redirected. Only the success path delivers to the requested (now-registered)
        // redirect_uri; the issued code is additionally bound to that exact URI and to the PKCE
        // challenge, so the token endpoint re-checks both before any token is minted.
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
        AuthorizationRequest request;
        try {
            request = new AuthorizationRequest(
                    realm,
                    clientId,
                    redirectUri,
                    parseScopes(scope),
                    state,
                    // OIDC Core §3.1.2.1 makes nonce OPTIONAL for the code flow, so an
                    // omitted nonce is a valid request, not a 400. Rejecting it — as this
                    // endpoint used to — turned away spec-conformant relying parties. This
                    // endpoint serves response_type=code and nothing else (see the check
                    // above), so the flows where nonce is REQUIRED — implicit (§3.2.2.1)
                    // and hybrid (§3.3.2.1) — are unreachable here: there is no response
                    // type this server answers for which a missing nonce is a violation.
                    //
                    // An EMPTY nonce= is normalised to absent rather than rejected, because
                    // RFC 6749 §3.1 requires it: "Parameters sent without a value MUST be
                    // treated as if they were omitted from the request." The domain record
                    // separately refuses to REPRESENT a blank nonce, so an empty value can
                    // never survive as an empty `nonce` claim in an ID token — the wire
                    // normalises, the domain forbids, and neither relies on the other.
                    //
                    // PKCE, which is what actually binds this code to this client, stays
                    // mandatory and unchanged.
                    isBlank(nonce) ? null : nonce,
                    CodeChallenge.s256(codeChallenge));
        } catch (IllegalArgumentException ex) {
            // A malformed challenge (wrong length / alphabet) or other structural problem.
            return badRequest(AuthorizationError.INVALID_REQUEST, ex.getMessage());
        }

        if (isBlank(subjectId)) {
            return signIn.begin(request).map(result -> switch (result) {
                case BeginResult.Started started -> Response.seeOther(uriInfo.getBaseUriBuilder()
                                .path("signin")
                                .queryParam("txn", started.transactionId())
                                .build())
                        .cookie(SignInCookies.issue(
                                uriInfo, started.binding(), started.lifetime().toSeconds()))
                        .header("Cache-Control", "no-store")
                        .build();
                case BeginResult.Refused refused -> errorBody(refused.error(), refused.description());
            });
        }

        return authorize.authorize(request, subjectId)
                .map(result -> render(result, redirectUri, state));
    }

    private Response render(AuthorizeResult result, String redirectUri, String state) {
        return switch (result) {
            case AuthorizeResult.Issued issued -> redirect(AuthorizationResponses.success(
                    redirectUri, issued.code(), issued.state(), config.issuer()));
            case AuthorizeResult.Failed failed -> failed.redirectable()
                    ? redirect(AuthorizationResponses.error(
                            redirectUri, failed.error(), failed.description(), state, config.issuer()))
                    : errorBody(failed.error(), failed.description());
        };
    }

    /** A 302 redirect (RFC 6749 uses 302; the authorization response is delivered in the URI). */
    private static Response redirect(URI location) {
        return Response.status(Response.Status.FOUND).location(location).build();
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

    private static Set<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
