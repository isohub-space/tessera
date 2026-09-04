package dev.tessera.iam.adapter.rest.login;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.SessionUseCase;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The logout endpoint ({@code POST /logout}) — ends the caller's session and clears the
 * cookie. Idempotent: logging out with no cookie, an unknown session id, or an already-ended
 * session all succeed identically (a {@code 204} and a cleared cookie).
 */
@Path("/logout")
@Tag(name = "login", description = "End-user login (IAM-49): verifies a credential and establishes a session.")
@TenantScoped
public class LogoutResource {

    @Inject
    SessionUseCase sessions;

    @Inject
    TenantContext tenantContext;

    @POST
    @Operation(operationId = "logout", summary = "End the caller's session")
    public Uni<Response> logout(@Context HttpHeaders headers) {
        RealmKey realm = tenantContext.realm();
        Cookie cookie = headers.getCookies().get(SessionCookies.NAME);
        Uni<Void> invalidated = (cookie == null || cookie.getValue() == null)
                ? Uni.createFrom().voidItem()
                : invalidate(realm, cookie.getValue());
        return invalidated.map(ignored -> Response.noContent()
                .cookie(SessionCookies.clear())
                .build());
    }

    private Uni<Void> invalidate(RealmKey realm, String rawSessionId) {
        try {
            return sessions.logout(realm, SessionId.fromString(rawSessionId));
        } catch (IllegalArgumentException malformed) {
            // A garbled cookie value ends nothing, but logout still succeeds and clears it.
            return Uni.createFrom().voidItem();
        }
    }
}
