package dev.tessera.iam.application;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Application service for the authorization endpoint: validates an authorization request
 * against the registered client and mints a single-use, tenant-scoped authorization code.
 *
 * <p>Framework-free (no CDI annotations): an adapter constructs it from the outbound ports
 * and a {@link Clock} and exposes it as a bean. All reactivity is in the {@link Uni} fold;
 * the security-relevant decisions (registered redirect URI, allowed grant) are explicit
 * branches, and the code/clock/randomness effects are confined to the injected ports.
 */
public final class AuthorizationService implements AuthorizeUseCase {

    private static final GrantType AUTHORIZATION_CODE = new AuthorizationCode();

    private final ClientRepositoryPort clients;
    private final AuthorizationCodeStorePort codeStore;
    private final OpaqueIdentifierPort identifiers;
    private final Clock clock;
    private final Duration codeTtl;

    public AuthorizationService(
            ClientRepositoryPort clients,
            AuthorizationCodeStorePort codeStore,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            Duration codeTtl) {
        this.clients = requireNonNull(clients, "clients");
        this.codeStore = requireNonNull(codeStore, "codeStore");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.clock = requireNonNull(clock, "clock");
        this.codeTtl = requireNonNull(codeTtl, "codeTtl");
        if (codeTtl.isZero() || codeTtl.isNegative()) {
            throw new IllegalArgumentException("codeTtl must be positive");
        }
    }

    @Override
    public Uni<AuthorizeResult> authorize(AuthorizationRequest request, String subjectId) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }

        return clients.findByClientId(request.realm(), request.clientId())
                .flatMap(client -> {
                    if (client == null) {
                        // Unknown client: an error that must NOT be redirected (the redirect
                        // URI itself is untrusted until the client is validated).
                        return failed(AuthorizationError.INVALID_REQUEST,
                                "unknown client", false);
                    }
                    if (!client.allowedGrants().contains(AUTHORIZATION_CODE)) {
                        return failed(AuthorizationError.UNAUTHORIZED_CLIENT,
                                "client may not use the authorization_code grant", false);
                    }
                    return issueCode(request, client, subjectId);
                });
    }

    private Uni<AuthorizeResult> issueCode(AuthorizationRequest request, Client client, String subjectId) {
        Instant now = clock.instant();
        AuthorizationGrant grant = new AuthorizationGrant(
                request.realm(),
                client.id(),
                subjectId,
                request.redirectUri(),
                request.scopes(),
                request.nonce(),
                request.codeChallenge(),
                now,
                now.plus(codeTtl));
        String code = identifiers.newAuthorizationCode();
        return codeStore.store(code, grant)
                .replaceWith(success(code, request.state()));
    }

    private static Uni<AuthorizeResult> success(String code, String state) {
        return Uni.createFrom().item(new AuthorizeResult.Issued(code, state));
    }

    private static Uni<AuthorizeResult> failed(
            AuthorizationError error, String description, boolean redirectable) {
        return Uni.createFrom().item(new AuthorizeResult.Failed(error, description, redirectable));
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
