package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.dto.DiscoveryDto;
import dev.tessera.iam.domain.oidc.DiscoveryDocument;
import dev.tessera.iam.domain.oidc.OidcCapabilities;
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
 * The OIDC discovery endpoint: publishes the OpenID Provider metadata document at
 * {@code GET /.well-known/openid-configuration} (OpenID Connect Discovery 1.0 / RFC 8414).
 *
 * <p>The document is generated from the enforced capability set
 * ({@link OidcCapabilities#enforced()}): every advertised {@code *_supported} value is
 * read from the same declaration the server enforces at request time, so discovery can
 * never advertise a capability the server would reject. The {@code issuer} is taken from
 * server configuration for the resolved realm — it is <strong>never</strong> derived from
 * the request {@code Host} header.
 *
 * <p>Responses carry a short {@code Cache-Control} max-age, deliberately shorter than the
 * PENDING dwell, so a verifier re-fetches the JWKS and pre-trusts a {@code PENDING} key
 * before it is promoted to signing.
 */
@Path("/.well-known/openid-configuration")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "discovery", description = "OpenID Provider metadata (OIDC Discovery).")
public class DiscoveryResource {

    @Inject
    OidcDiscoveryConfig config;

    @GET
    @Operation(
            operationId = "getOpenIdConfiguration",
            summary = "OpenID Provider metadata document (OIDC Discovery)")
    @APIResponse(
            responseCode = "200",
            description = "The OpenID Provider metadata, generated from the enforced capability set.",
            content = @Content(schema = @Schema(implementation = DiscoveryDto.class)))
    public Uni<RestResponse<DiscoveryDto>> openIdConfiguration(
            @HeaderParam("X-Tenant-Id") String tenantHeader,
            @HeaderParam("X-Baseline-Id") String baselineHeader) {
        // Realm is resolved for fail-closed tenant scoping; the issuer is server config
        // per resolved realm (baseline tier: one configured issuer), never the Host header.
        RealmKey realm = realm(tenantHeader, baselineHeader);
        String issuer = issuerFor(realm);
        DiscoveryDocument doc = DiscoveryDocument.forIssuer(issuer, OidcCapabilities.enforced());
        DiscoveryDto dto = DiscoveryDto.from(doc);
        return Uni.createFrom().item(
                RestResponse.ResponseBuilder.ok(dto)
                        .header("Cache-Control", cacheControl())
                        .build());
    }

    /**
     * The configured issuer for the resolved realm. For the baseline tier a single
     * configured issuer serves every realm; per-realm / per-tenant issuers are a later
     * tier. The issuer is server configuration and is never inferred from the request.
     */
    private String issuerFor(RealmKey realm) {
        return config.issuer();
    }

    private String cacheControl() {
        return "public, max-age=" + config.jwks().cacheTtlSeconds();
    }

    /**
     * Resolves the realm from the tenant headers (fail-closed). {@code X-Tenant-Id} is
     * required; {@code X-Baseline-Id} defaults to the zero baseline when absent.
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
