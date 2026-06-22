package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.dto.JwkSetDto;
import dev.tessera.iam.application.port.out.KeyProviderPort;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.UUID;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.resteasy.reactive.RestResponse;

/**
 * The JWKS endpoint: publishes a realm's public verification keys as a JWK Set
 * (RFC 7517 §5), so any relying party can verify the JWTs this server signs.
 *
 * <ul>
 *   <li>{@code GET /jwks}</li>
 *   <li>{@code GET /.well-known/jwks.json} (the conventional well-known alias)</li>
 * </ul>
 *
 * <p>The document contains every published key — {@code PENDING}, {@code ACTIVE} and
 * {@code RETIRING} (only {@code RETIRED} is withdrawn). A {@code PENDING} key is published
 * before it is promoted to {@code ACTIVE} and signs, so a verifier can pre-trust it
 * (publish-before-sign); a {@code RETIRING} key stays published so a token signed just
 * before a rotation still verifies. <strong>No private key material is ever served</strong>
 * — the response is built from public JWKs alone, sourced through the signing-key provider
 * port (signing stays inside the provider).
 *
 * <p>Responses carry a {@code Cache-Control} max-age that is deliberately shorter than the
 * PENDING dwell (how long a key stays {@code PENDING} before it signs), so a verifier's
 * cache expires and it re-fetches — picking up a {@code PENDING} key — before that key is
 * promoted to {@code ACTIVE} and signs.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "jwks", description = "Published public verification keys (JWK Set).")
public class JwksResource {

    @Inject
    KeyProviderPort keyProvider;

    @Inject
    OidcDiscoveryConfig config;

    @GET
    @Path("jwks")
    @Operation(operationId = "getJwks", summary = "Published public verification keys (JWK Set)")
    @APIResponse(
            responseCode = "200",
            description = "The realm's published (PENDING + ACTIVE + RETIRING) public keys.",
            content = @Content(schema = @Schema(implementation = JwkSetDto.class)))
    public Uni<RestResponse<JwkSetDto>> jwks(
            @HeaderParam("X-Tenant-Id") String tenantHeader,
            @HeaderParam("X-Baseline-Id") String baselineHeader) {
        RealmKey realm = realm(tenantHeader, baselineHeader);
        return keyProvider.publishedJwks(realm)
                .map(JwkSetDto::from)
                .map(set -> RestResponse.ResponseBuilder.ok(set)
                        .header("Cache-Control", cacheControl())
                        .build());
    }

    @GET
    @Path(".well-known/jwks.json")
    @Operation(
            operationId = "getWellKnownJwks",
            summary = "Published public verification keys (JWK Set), well-known alias")
    @APIResponse(
            responseCode = "200",
            description = "The realm's published (PENDING + ACTIVE + RETIRING) public keys.",
            content = @Content(schema = @Schema(implementation = JwkSetDto.class)))
    public Uni<RestResponse<JwkSetDto>> wellKnownJwks(
            @HeaderParam("X-Tenant-Id") String tenantHeader,
            @HeaderParam("X-Baseline-Id") String baselineHeader) {
        return jwks(tenantHeader, baselineHeader);
    }

    private String cacheControl() {
        return "public, max-age=" + config.jwks().cacheTtlSeconds();
    }

    /**
     * Resolves the realm from the tenant headers. Full request-scoped tenant
     * propagation (gateway → context) is handled elsewhere; here the realm is taken
     * directly from {@code X-Tenant-Id} (and an optional {@code X-Baseline-Id}), with a
     * zero baseline when none is supplied.
     */
    private static RealmKey realm(String tenantHeader, String baselineHeader) {
        if (tenantHeader == null || tenantHeader.isBlank()) {
            throw new jakarta.ws.rs.BadRequestException("Missing X-Tenant-Id header");
        }
        TenantId tenant = new TenantId(UUID.fromString(tenantHeader));
        BaselineId baseline = (baselineHeader == null || baselineHeader.isBlank())
                ? new BaselineId(new UUID(0L, 0L))
                : new BaselineId(UUID.fromString(baselineHeader));
        return new RealmKey(tenant, baseline);
    }
}
