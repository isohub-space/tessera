package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.application.AuthorizationService;
import dev.tessera.iam.application.IntrospectService;
import dev.tessera.iam.application.ItemService;
import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.RevokeService;
import dev.tessera.iam.application.TokenService;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.in.QueryItemsUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.time.Clock;

/**
 * CDI wiring for the application use cases.
 *
 * <p>The application services are framework-free (no CDI annotations), so the adapter
 * constructs each from its injected outbound ports, configuration and a {@link Clock}, and
 * exposes it as a bean. This is the single composition seam between the framework-free core
 * and the adapter shell for the read API and the Authorization Code + PKCE flow.
 */
@ApplicationScoped
public class UseCaseProducer {

    @Produces
    @ApplicationScoped
    QueryItemsUseCase queryItemsUseCase(ItemRepositoryPort repository) {
        return new ItemService(repository);
    }

    @Produces
    @ApplicationScoped
    Clock systemClock() {
        return Clock.systemUTC();
    }

    @Produces
    @ApplicationScoped
    AuthorizeUseCase authorizeUseCase(
            ClientRepositoryPort clients,
            AuthorizationCodeStorePort codeStore,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            AuthFlowConfig authFlow) {
        return new AuthorizationService(clients, codeStore, identifiers, clock, authFlow.codeTtl());
    }

    @Produces
    @ApplicationScoped
    TokenUseCase tokenUseCase(
            ClientRepositoryPort clients,
            AuthorizationCodeStorePort codeStore,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            DpopProofValidatorPort dpop,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow,
            RefreshConfig refresh) {
        return new TokenService(
                clients,
                codeStore,
                secretVerifier,
                signer,
                dpop,
                identifiers,
                refreshStore,
                clock,
                oidc.issuer(),
                tokenEndpoint(oidc.issuer()),
                authFlow.accessTokenTtl(),
                authFlow.idTokenTtl(),
                refresh.refreshTokenTtl(),
                refresh.enabled());
    }

    /**
     * The token endpoint URL a DPoP proof's {@code htu} must match (RFC 9449 §4.2). Derived
     * from the configured issuer — never from the request Host — so a client cannot bind a
     * proof to a foreign authority. Mirrors how OIDC discovery derives endpoint URLs.
     */
    private static String tokenEndpoint(String issuer) {
        return issuer.replaceAll("/+$", "") + "/token";
    }

    @Produces
    @ApplicationScoped
    RefreshUseCase refreshUseCase(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            RefreshTokenTenantResolverPort tenantResolver,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow,
            RefreshConfig refresh) {
        return new RefreshService(
                clients,
                secretVerifier,
                signer,
                identifiers,
                refreshStore,
                tenantResolver,
                clock,
                oidc.issuer(),
                authFlow.accessTokenTtl(),
                refresh.enabled());
    }

    @Produces
    @ApplicationScoped
    RevokeUseCase revokeUseCase(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            RefreshTokenStorePort refreshStore) {
        return new RevokeService(clients, secretVerifier, refreshStore);
    }

    @Produces
    @ApplicationScoped
    IntrospectUseCase introspectUseCase(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            RefreshTokenStorePort refreshStore,
            AccessTokenIntrospectorPort accessTokens,
            Clock clock) {
        return new IntrospectService(clients, secretVerifier, refreshStore, accessTokens, clock);
    }
}
