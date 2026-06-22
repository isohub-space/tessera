package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.application.AuthorizationService;
import dev.tessera.iam.application.ItemService;
import dev.tessera.iam.application.TokenService;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.QueryItemsUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
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
            OpaqueIdentifierPort identifiers,
            Clock clock,
            OidcDiscoveryConfig oidc,
            AuthFlowConfig authFlow) {
        return new TokenService(
                clients,
                codeStore,
                secretVerifier,
                signer,
                identifiers,
                clock,
                oidc.issuer(),
                authFlow.accessTokenTtl(),
                authFlow.idTokenTtl());
    }
}
