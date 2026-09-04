package dev.tessera.iam.adapter.rest.login;

import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase.LoginResult;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The login endpoint ({@code POST /login}) — verifies a username/password and, on success,
 * establishes a session, returned as a cookie ({@link SessionCookies}).
 *
 * <p>This is the missing half of the seam {@code AuthorizeResource} names in its own
 * javadoc: {@code /authorize} still reads the subject from {@code X-Subject-Id}, unchanged;
 * this endpoint is what a user agent calls first, and
 * {@link dev.tessera.iam.adapter.rest.session.SessionCookieFilter} is what later fills that
 * header from the cookie this endpoint sets.
 *
 * <p>Deliberately minimal: no HTML is served here (this is a JSON protocol server — see the
 * module README on what tessera is not yet) — a real deployment fronts this with its own
 * login page/form that posts here. The response carries no body on success; the session is
 * entirely represented by the cookie.
 */
@Path("/login")
@Tag(name = "login", description = "End-user login (IAM-49): verifies a credential and establishes a session.")
@TenantScoped
@RateLimited
public class LoginResource {

    @Inject
    LoginUseCase login;

    @Inject
    TenantContext tenantContext;

    @Inject
    LoginConfig config;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "login", summary = "Verify a username/password and establish a session")
    public Uni<Response> login(
            @FormParam("username") String username, @FormParam("password") String password) {
        if (isBlank(username) || isBlank(password)) {
            return Uni.createFrom().item(Response.status(Response.Status.BAD_REQUEST)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(new OAuthErrorDto("invalid_request", "username and password are required"))
                    .build());
        }

        RealmKey realm = tenantContext.realm();
        return login.login(realm, username, password).map(this::render);
    }

    private Response render(LoginResult result) {
        return switch (result) {
            case LoginResult.Authenticated authenticated -> Response.noContent()
                    .cookie(SessionCookies.issue(
                            authenticated.sessionId().toString(),
                            config.sessionTtl().toSeconds()))
                    .build();
            // Deliberately the SAME status/body for every denial reason (unknown username,
            // wrong password) — see LoginUseCase.LoginResult.Denied.
            case LoginResult.Denied denied -> Response.status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(new OAuthErrorDto("invalid_credentials", "invalid username or password"))
                    .build();
        };
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
