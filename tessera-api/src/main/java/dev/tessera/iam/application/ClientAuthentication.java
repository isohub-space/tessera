package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * The one client-authentication step shared by {@code /token} ({@code client_credentials}),
 * {@code /introspect} and {@code /revoke}, at the same cost whatever the outcome.
 *
 * <p>The secret verifier runs exactly once on every request: against the client's own id for a
 * confidential client of the realm, and against {@link ClientSecretVerifierPort#unknownClient}
 * for the presented id otherwise (unknown, another tenant's, or public), with {@code ""} when no
 * secret was presented. So neither the response time nor the failure throttle tells whether a
 * {@code client_id} exists.
 */
final class ClientAuthentication {

    private ClientAuthentication() {
    }

    /**
     * @param client               the client the realm resolved for the presented id, or {@code null}
     * @param publicClientsAllowed whether a public client is identified by its {@code client_id}
     *                             alone, as introspection and revocation allow (RFC 7662 §4)
     * @return {@code true} when the client is authenticated
     */
    static Uni<Boolean> authenticate(
            ClientSecretVerifierPort verifier, RealmKey realm, String presentedClientId, Client client,
            String presentedSecret, boolean publicClientsAllowed) {
        boolean confidential = client instanceof ConfidentialClient;
        String secret = presentedSecret == null ? "" : presentedSecret;
        return verifier.verifySecret(realm,
                        confidential ? client.id() : ClientSecretVerifierPort.unknownClient(presentedClientId), secret)
                .map(verified -> confidential
                        ? Boolean.TRUE.equals(verified)
                        : publicClientsAllowed && client instanceof PublicClient);
    }
}
