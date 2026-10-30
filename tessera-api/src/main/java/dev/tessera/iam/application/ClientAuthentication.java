package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
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
 *
 * <p>A client authenticates with the one method it is registered for. A {@code private_key_jwt}
 * or workload-identity client has no secret, so its secret is verified against the sentinel and
 * fails; a client presenting a JWT assertion ({@link #authenticateAssertion}) is accepted only when
 * it is registered for one of those two assertion methods, and the assertion path runs the same
 * steps for every other client too.
 */
final class ClientAuthentication {

    private ClientAuthentication() {
    }

    /**
     * @param client               the client the realm resolved for the presented id, or {@code null}
     * @param publicClientsAllowed whether a public client is identified by its {@code client_id}
     *                             alone, as revocation allows for the tokens issued to it
     *                             (RFC 7009 §2.1); introspection and {@code client_credentials}
     *                             do not
     * @return {@code true} when the client is authenticated
     */
    static Uni<Boolean> authenticate(
            ClientSecretVerifierPort verifier, RealmKey realm, String presentedClientId, Client client,
            String presentedSecret, boolean publicClientsAllowed) {
        boolean confidential = client instanceof ConfidentialClient c && !byAssertion(c);
        String secret = presentedSecret == null ? "" : presentedSecret;
        return verifier.verifySecret(realm,
                        confidential ? client.id() : ClientSecretVerifierPort.unknownClient(presentedClientId), secret)
                .map(verified -> confidential
                        ? Boolean.TRUE.equals(verified)
                        : publicClientsAllowed && client instanceof PublicClient);
    }

    /**
     * Authenticates a client by a JWT assertion (RFC 7523 §2.2). The key source and the verifier
     * each run exactly once on every request: for a client registered for {@code private_key_jwt}
     * or a workload identity against its own id, otherwise against the sentinel for the presented id, whose missing trust
     * the verifier answers with a failing signature check. An unknown client, a secret client, a
     * wrong key and a bad claim are therefore refused alike.
     *
     * @return {@code true} when the client is authenticated
     */
    static Uni<Boolean> authenticateAssertion(
            ClientKeySourcePort keys, ClientAssertionVerifierPort assertions, RealmKey realm,
            String presentedClientId, Client client, String assertion) {
        boolean keyed = client instanceof ConfidentialClient c && byAssertion(c);
        ClientId id = keyed ? client.id() : ClientSecretVerifierPort.unknownClient(presentedClientId);
        return keys.trustFor(realm, id)
                .flatMap(trust -> assertions.verify(realm, keyed ? trust : null, assertion))
                .map(verified -> keyed && Boolean.TRUE.equals(verified));
    }

    /** Whether the client authenticates by a JWT assertion rather than a secret. */
    private static boolean byAssertion(ConfidentialClient client) {
        return client.authMethod() == ClientAuthMethod.PRIVATE_KEY_JWT
                || client.authMethod() == ClientAuthMethod.WORKLOAD_IDENTITY;
    }
}
