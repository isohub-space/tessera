package dev.tessera.iam.adapter.rest.login;

import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.EndSessionUseCase;
import dev.tessera.iam.application.port.in.EndSessionUseCase.EndSessionCommand;
import dev.tessera.iam.application.port.in.EndSessionUseCase.EndSessionOutcome;
import dev.tessera.iam.domain.session.SessionId;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The end-session endpoint ({@code /end_session}, OpenID Connect RP-Initiated Logout 1.0),
 * advertised in discovery as {@code end_session_endpoint}. A relying party sends the user's
 * browser here, by {@code GET} or by a form {@code POST} (§2), to end the user's session at this
 * server, so that signing in again asks for the credential.
 *
 * <p>The rules live in {@link EndSessionUseCase}; this resource maps them to HTTP:
 * <ul>
 *   <li>Accepted with a {@code post_logout_redirect_uri}: {@code 303} to that registered URI, with
 *       {@code state} appended when sent.</li>
 *   <li>Accepted without one: {@code 200} with a short page saying the user is signed out.</li>
 *   <li>Refused: {@code 400} {@code invalid_request} with no {@code Location}, whatever the
 *       request asked for. A refused request ends nothing and does not touch the cookie.</li>
 * </ul>
 *
 * <p>An accepted request always clears the session cookie, with the flags it was issued with
 * ({@link SessionCookies#clear()}), whether or not a session was still live. Every response is
 * {@code no-store}. The endpoint is reached only by top-level navigation, so it is kept outside
 * the CORS policy like {@code /authorize}: no origin may call it from script.
 */
@Path("/end_session")
@Tag(name = "login", description = "End-user login: verifies a credential and establishes a session.")
@TenantScoped
@RateLimited
public class EndSessionResource {

    private static final String SIGNED_OUT_PAGE = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            + "<title>Signed out</title></head><body><p>You are signed out.</p></body></html>";

    @Inject
    EndSessionUseCase endSession;

    @Inject
    TenantContext tenantContext;

    @GET
    @Operation(operationId = "endSession", summary = "End the user's session (RP-initiated logout)")
    public Uni<Response> endSessionByQuery(
            @Context HttpHeaders headers,
            @QueryParam("id_token_hint") String idTokenHint,
            @QueryParam("client_id") String clientId,
            @QueryParam("post_logout_redirect_uri") String postLogoutRedirectUri,
            @QueryParam("state") String state) {
        return handle(headers, idTokenHint, clientId, postLogoutRedirectUri, state);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Operation(operationId = "endSessionByForm", summary = "End the user's session (RP-initiated logout, form post)")
    public Uni<Response> endSessionByForm(
            @Context HttpHeaders headers,
            @FormParam("id_token_hint") String idTokenHint,
            @FormParam("client_id") String clientId,
            @FormParam("post_logout_redirect_uri") String postLogoutRedirectUri,
            @FormParam("state") String state) {
        return handle(headers, idTokenHint, clientId, postLogoutRedirectUri, state);
    }

    private Uni<Response> handle(
            HttpHeaders headers, String idTokenHint, String clientId, String postLogoutRedirectUri, String state) {
        EndSessionCommand command = new EndSessionCommand(tenantContext.realm(), idTokenHint, clientId,
                postLogoutRedirectUri, state, presentedSession(headers));
        return endSession.endSession(command).map(EndSessionResource::toResponse);
    }

    private static Response toResponse(EndSessionOutcome outcome) {
        return switch (outcome) {
            case EndSessionOutcome.Redirect redirect -> Response.seeOther(URI.create(redirect.location()))
                    .cookie(SessionCookies.clear())
                    .header("Cache-Control", "no-store")
                    .build();
            case EndSessionOutcome.SignedOut signedOut -> Response.ok(SIGNED_OUT_PAGE, MediaType.TEXT_HTML_TYPE)
                    .cookie(SessionCookies.clear())
                    .header("Cache-Control", "no-store")
                    .build();
            case EndSessionOutcome.Refused refused -> Response.status(Response.Status.BAD_REQUEST)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(new OAuthErrorDto("invalid_request", refused.description()))
                    .header("Cache-Control", "no-store")
                    .build();
        };
    }

    /** The session the browser presented, or {@code null} for none or a malformed cookie value. */
    private static SessionId presentedSession(HttpHeaders headers) {
        Cookie cookie = headers.getCookies().get(SessionCookies.NAME);
        if (cookie == null || cookie.getValue() == null || cookie.getValue().isBlank()) {
            return null;
        }
        try {
            return SessionId.fromString(cookie.getValue());
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }
}
