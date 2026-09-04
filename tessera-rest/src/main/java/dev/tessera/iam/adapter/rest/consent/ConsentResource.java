package dev.tessera.iam.adapter.rest.consent;

import dev.tessera.iam.adapter.rest.dto.OAuthErrorDto;
import dev.tessera.iam.adapter.rest.problem.ProblemResponse;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.ConsentUseCase;
import dev.tessera.iam.domain.client.ClientId;
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
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The consent endpoint ({@code POST /consent}) — records which scopes an already-authenticated
 * end user agrees to release to a client (IAM-49 AC4).
 *
 * <p>Reuses the same {@code X-Subject-Id} seam as {@code /authorize}: this endpoint only runs
 * after {@link dev.tessera.iam.adapter.rest.session.SessionCookieFilter} has (potentially)
 * filled it from the session cookie, so "no subject" here means the same thing it means at
 * {@code /authorize} — no established session — and is refused identically
 * ({@code access_denied}), never a distinguishable error that would help a caller probe for a
 * live session.
 */
@Path("/consent")
@Tag(name = "consent", description = "Records end-user consent for a client's requested scopes (IAM-49).")
@TenantScoped
public class ConsentResource {

    @Inject
    ConsentUseCase consent;

    @Inject
    TenantContext tenantContext;

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(operationId = "consent", summary = "Record the caller's consent for a client's requested scopes")
    public Uni<Response> grant(
            @HeaderParam("X-Subject-Id") String subjectId,
            @FormParam("client_id") String clientId,
            @FormParam("scope") String scope) {
        if (isBlank(subjectId)) {
            // Same non-oracle refusal as /authorize's missing-subject path.
            return Uni.createFrom().item(Response.status(Response.Status.UNAUTHORIZED)
                    .type(MediaType.APPLICATION_JSON)
                    .entity(new OAuthErrorDto("access_denied", "no authenticated subject"))
                    .build());
        }
        if (isBlank(clientId)) {
            return Uni.createFrom().item(ProblemResponse.badRequest("client_id is required"));
        }

        RealmKey realm = tenantContext.realm();
        ClientId client;
        try {
            client = ClientId.fromString(clientId);
        } catch (IllegalArgumentException malformed) {
            return Uni.createFrom().item(ProblemResponse.badRequest("client_id must be a valid identifier"));
        }

        return consent.recordConsent(realm, subjectId, client, parseScopes(scope))
                .replaceWith(Response.noContent().build());
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
