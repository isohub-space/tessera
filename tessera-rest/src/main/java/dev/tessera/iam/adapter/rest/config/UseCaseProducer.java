package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.adapter.rest.login.LoginConfig;
import dev.tessera.iam.application.AuthorizationService;
import dev.tessera.iam.application.ConsentService;
import dev.tessera.iam.application.IntrospectService;
import dev.tessera.iam.application.LoginService;
import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.RevokeService;
import dev.tessera.iam.application.SessionService;
import dev.tessera.iam.application.TokenService;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.ConsentUseCase;
import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.in.SessionUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.time.Clock;
import java.util.Base64;

/**
 * CDI wiring for the application use cases.
 *
 * <p>The application services are framework-free (no CDI annotations), so the adapter
 * constructs each from its injected outbound ports, configuration and a {@link Clock}, and
 * exposes it as a bean. This is the single composition seam between the framework-free core
 * and the adapter shell for the Authorization Code + PKCE flow and the login/consent surface.
 */
@ApplicationScoped
public class UseCaseProducer {

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
                refresh.enabled(),
                authFlow.requireSenderConstraint());
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
    @Startup
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
                authFlow.idTokenTtl(),
                refresh.enabled(),
                refresh.reuseGrace(),
                successorKey(refresh));
    }

    /**
     * The decoded successor key, or {@code null} when no reuse grace is configured. A positive grace
     * without a usable key fails here, at start-up, rather than on the first refresh.
     */
    private static byte[] successorKey(RefreshConfig refresh) {
        if (refresh.reuseGrace().isZero()) {
            return null;
        }
        byte[] key;
        try {
            key = refresh.successorKey()
                    .filter(k -> !k.isBlank())
                    .map(k -> Base64.getDecoder().decode(k.trim()))
                    .orElse(null);
        } catch (IllegalArgumentException notBase64) {
            throw new IllegalStateException("iam.refresh.successor-key is not valid base64");
        }
        if (key == null || key.length < 32) {
            throw new IllegalStateException("iam.refresh.reuse-grace is " + refresh.reuseGrace()
                    + " but iam.refresh.successor-key is missing or shorter than 32 bytes");
        }
        return key;
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

    @Produces
    @ApplicationScoped
    LoginUseCase loginUseCase(
            PasswordCredentialVerifierPort credentials, SessionStorePort sessions, LoginConfig login) {
        return new LoginService(credentials, sessions, login.sessionTtl());
    }

    @Produces
    @ApplicationScoped
    SessionUseCase sessionUseCase(SessionStorePort sessions) {
        return new SessionService(sessions);
    }

    @Produces
    @ApplicationScoped
    ConsentUseCase consentUseCase(ConsentStorePort consents) {
        return new ConsentService(consents);
    }
}
