package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.ClientCredentialsUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.ClaimSourcePort;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.IssuedTokenClaims;
import dev.tessera.iam.domain.authflow.ClaimContributor;
import dev.tessera.iam.domain.authflow.Subject;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.token.ClaimSet;
import dev.tessera.iam.domain.token.Confirmation;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Application service for the {@code client_credentials} grant (RFC 6749 §4.4): a confidential
 * client authenticates and receives an RFC 9068 access token on its own behalf.
 *
 * <p>The checks run in a fixed order, and each refusal is the RFC 6749 §5.2 error for it:
 * <ol>
 *   <li>the client exists in the request's realm, is confidential and authenticates with the
 *       method it is registered for, a secret or a JWT assertion ({@code invalid_client}
 *       otherwise: an unknown client, a public client, a wrong secret, a wrong key and a bad
 *       assertion claim look the same, in the answer and in the time it takes, and a client of
 *       another tenant is invisible under row-level security);</li>
 *   <li>the client is registered for the grant ({@code unauthorized_client});</li>
 *   <li>every requested scope is registered for it ({@code invalid_scope}); with none requested
 *       it is granted all its registered scopes;</li>
 *   <li>every {@code resource} indicator names one of its registered audiences
 *       ({@code invalid_target}, RFC 8707): an indicator can narrow the audience, never widen it,
 *       and a client with no registered audience is issued no token, because {@code aud} is never
 *       the issuer;</li>
 *   <li>the token is sender-constrained by the client certificate exactly as on the
 *       authorization-code path.</li>
 * </ol>
 *
 * <p>The token's {@code sub} and {@code client_id} are the client. Its roles come from the
 * client's registration through {@link ClaimSourcePort} and {@link ClaimContributor}, and the
 * realm claims are stamped last, so nothing upstream can change the tenant a token names. No
 * refresh token is issued (RFC 6749 §4.4.3).
 */
public final class ClientCredentialsService implements ClientCredentialsUseCase {

    private static final String TOKEN_TYPE_BEARER = "Bearer";

    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final ClientKeySourcePort keySource;
    private final ClientAssertionVerifierPort assertionVerifier;
    private final ClaimSourcePort claimSource;
    private final TokenSignerPort signer;
    private final OpaqueIdentifierPort identifiers;
    private final Clock clock;
    private final String issuer;
    private final Duration accessTokenTtl;
    private final boolean requireSenderConstraint;
    private final ClaimContributor contributor = new ClaimContributor();

    /**
     * @param requireSenderConstraint whether a client that presents no certificate is refused
     *                                ({@code true}) or issued a plain Bearer token; the same
     *                                setting as the authorization-code path
     */
    public ClientCredentialsService(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            ClientKeySourcePort keySource,
            ClientAssertionVerifierPort assertionVerifier,
            ClaimSourcePort claimSource,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            String issuer,
            Duration accessTokenTtl,
            boolean requireSenderConstraint) {
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.keySource = requireNonNull(keySource, "keySource");
        this.assertionVerifier = requireNonNull(assertionVerifier, "assertionVerifier");
        this.claimSource = requireNonNull(claimSource, "claimSource");
        this.signer = requireNonNull(signer, "signer");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.clock = requireNonNull(clock, "clock");
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        this.issuer = issuer;
        requireNonNull(accessTokenTtl, "accessTokenTtl");
        if (accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("accessTokenTtl must be positive");
        }
        this.accessTokenTtl = accessTokenTtl;
        this.requireSenderConstraint = requireSenderConstraint;
    }

    @Override
    public Uni<TokenResult> issue(ClientCredentialsCommand command) {
        requireNonNull(command, "command");
        return clients.findByClientId(command.realm(), command.clientId())
                .flatMap(client -> authenticate(command, client)
                        .flatMap(authenticated -> authenticated
                                ? authorize(command, (ConfidentialClient) client)
                                : failed(AuthorizationError.INVALID_CLIENT, "client authentication failed")));
    }

    /** Only a confidential client with a valid credential for its method authenticates, at uniform cost. */
    private Uni<Boolean> authenticate(ClientCredentialsCommand command, Client client) {
        if (command.clientAssertion() != null) {
            return ClientAuthentication.authenticateAssertion(keySource, assertionVerifier, command.realm(),
                    command.clientId(), client, command.clientAssertion());
        }
        return ClientAuthentication.authenticate(
                secretVerifier, command.realm(), command.clientId(), client, command.clientSecret(), false);
    }

    private Uni<TokenResult> authorize(ClientCredentialsCommand command, ConfidentialClient client) {
        if (client.allowedGrants().stream().noneMatch(ClientCredentials.class::isInstance)) {
            return failed(AuthorizationError.UNAUTHORIZED_CLIENT,
                    "the client is not registered for the client_credentials grant");
        }
        Set<String> scopes = requestedScopes(command.scope());
        if (scopes.isEmpty()) {
            scopes = client.allowedScopes();
        } else if (!client.allowedScopes().containsAll(scopes)) {
            return failed(AuthorizationError.INVALID_SCOPE,
                    "a requested scope is not registered for the client");
        }
        if (client.audiences().isEmpty()) {
            return failed(AuthorizationError.UNAUTHORIZED_CLIENT,
                    "the client has no registered audience");
        }
        Set<String> audience = new LinkedHashSet<>(command.resources());
        if (audience.isEmpty()) {
            audience = client.audiences();
        } else if (!client.audiences().containsAll(audience)) {
            return failed(AuthorizationError.INVALID_TARGET,
                    "a requested resource is not an audience of the client");
        }
        Confirmation cnf = null;
        if (command.certThumbprint() != null && !command.certThumbprint().isBlank()) {
            cnf = new Confirmation.MtlsX5tS256(command.certThumbprint());
        } else if (requireSenderConstraint || client.authMethod() == ClientAuthMethod.MTLS) {
            // The same rule as the authorization-code path (TokenService#resolveBinding).
            return failed(AuthorizationError.INVALID_REQUEST,
                    "a client certificate is required for a confidential client");
        }
        return mint(command, scopes, audience, cnf);
    }

    private Uni<TokenResult> mint(
            ClientCredentialsCommand command, Set<String> scopes, Set<String> audience, Confirmation cnf) {
        Instant now = clock.instant();
        Instant expiry = now.plus(accessTokenTtl);
        String clientId = command.clientId();
        String jti = identifiers.newTokenId();
        ClaimSet base = cnf == null
                ? IssuedTokenClaims.accessToken(issuer, clientId, clientId, audience, scopes, jti, now, expiry)
                : IssuedTokenClaims.accessToken(issuer, clientId, clientId, audience, scopes, jti, now, expiry, cnf);
        Set<String> granted = scopes;
        return claimSource.loadClaimContext(new Subject(clientId, command.realm()), command.realm(), granted)
                .map(context -> IssuedTokenClaims.withRealm(contributor.contribute(base, context), command.realm()))
                .flatMap(claims -> signer.sign(command.realm(), "at+jwt", claims))
                .map(token -> new TokenResult.Issued(
                        token, TOKEN_TYPE_BEARER, null, accessTokenTtl.toSeconds(),
                        String.join(" ", granted), null));
    }

    private static Set<String> requestedScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        Set<String> scopes = new LinkedHashSet<>();
        Arrays.stream(scope.trim().split(" +")).forEach(scopes::add);
        return scopes;
    }

    private static Uni<TokenResult> failed(AuthorizationError error, String description) {
        return Uni.createFrom().item(new TokenResult.Failed(error, description));
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
