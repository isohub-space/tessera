package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.dto.DiscoveryDto;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.domain.oidc.DiscoveryDocument;
import dev.tessera.iam.domain.oidc.OidcCapabilities;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
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
 *
 * <p>The realm is read from the request-scoped {@link TenantContext}, which the tenant
 * resolution filter populated from the gateway-asserted ingress headers — this resource
 * never parses the headers itself.
 */
@Path("/.well-known/openid-configuration")
@Produces(MediaType.APPLICATION_JSON)
@TenantScoped
@Tag(name = "discovery", description = "OpenID Provider metadata (OIDC Discovery).")
public class DiscoveryResource {

    @Inject
    OidcDiscoveryConfig config;

    @Inject
    TenantContext tenantContext;

    @GET
    @Operation(
            operationId = "getOpenIdConfiguration",
            summary = "OpenID Provider metadata document (OIDC Discovery)")
    @APIResponse(
            responseCode = "200",
            description = "The OpenID Provider metadata, generated from the enforced capability set.",
            content = @Content(schema = @Schema(implementation = DiscoveryDto.class)))
    public Uni<RestResponse<DiscoveryDto>> openIdConfiguration() {
        // Realm comes from the request-scoped context (resolved by the tenant filter); the
        // issuer is server config per resolved realm (baseline tier: one configured
        // issuer), never the Host header.
        RealmKey realm = tenantContext.realm();
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
}
