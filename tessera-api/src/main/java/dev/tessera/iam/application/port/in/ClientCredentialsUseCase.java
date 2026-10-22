package dev.tessera.iam.application.port.in;

import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.List;

/**
 * Inbound port for the {@code client_credentials} grant (RFC 6749 §4.4): a confidential client
 * obtains an access token on its own behalf.
 */
public interface ClientCredentialsUseCase {

    /**
     * Authenticates the client and issues an access token for it.
     *
     * @param command the token request (never {@code null})
     * @return a {@link Uni} emitting the {@link TokenResult}; never a refresh token
     */
    Uni<TokenResult> issue(ClientCredentialsCommand command);

    /**
     * A parsed {@code client_credentials} token request.
     *
     * @param realm          the realm the request runs within (never {@code null})
     * @param clientId       the wire {@code client_id} (never {@code null} or blank)
     * @param clientSecret   the presented client secret, or {@code null}
     * @param clientAssertion the presented JWT client assertion (RFC 7523 §2.2), or {@code null};
     *                       when present the client authenticates with it, never with a secret
     * @param scope          the requested {@code scope}, space-delimited, or {@code null} for the
     *                       client's registered scopes
     * @param resources      the RFC 8707 {@code resource} indicators, empty for the client's
     *                       registered audiences (never {@code null})
     * @param certThumbprint the {@code x5t#S256} thumbprint of the client certificate the edge
     *                       forwarded, or {@code null}
     */
    record ClientCredentialsCommand(
            RealmKey realm,
            String clientId,
            String clientSecret,
            String clientAssertion,
            String scope,
            List<String> resources,
            String certThumbprint) {

        /** A request authenticated by a client secret. */
        public ClientCredentialsCommand(RealmKey realm, String clientId, String clientSecret, String scope,
                List<String> resources, String certThumbprint) {
            this(realm, clientId, clientSecret, null, scope, resources, certThumbprint);
        }

        public ClientCredentialsCommand {
            if (realm == null) {
                throw new IllegalArgumentException("ClientCredentialsCommand realm must not be null");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("ClientCredentialsCommand clientId must not be blank");
            }
            if (clientSecret != null && clientAssertion != null) {
                throw new IllegalArgumentException("ClientCredentialsCommand takes one client credential");
            }
            resources = resources == null ? List.of() : List.copyOf(resources);
        }
    }
}
