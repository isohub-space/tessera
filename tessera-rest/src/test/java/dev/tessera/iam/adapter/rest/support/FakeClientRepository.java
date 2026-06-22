package dev.tessera.iam.adapter.rest.support;

import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;
import java.util.UUID;

/**
 * Test double for {@link ClientRepositoryPort} (the persistence-backed repository is owned
 * elsewhere). Resolves two fixed clients used by the flow tests:
 * <ul>
 *   <li>{@code public-spa} — a {@link PublicClient} allowed the authorization-code grant
 *       (PKCE-only, no secret);</li>
 *   <li>{@code confidential-web} — a {@link ConfidentialClient} that authenticates with a
 *       {@code client_secret} (verified by {@link FakeClientSecretVerifier});</li>
 *   <li>{@code no-code-client} — a confidential client that is <em>not</em> allowed the
 *       authorization-code grant, to exercise the {@code unauthorized_client} path.</li>
 * </ul>
 * Any other {@code client_id} resolves to {@code null} (unknown client). Resolution ignores
 * the realm beyond requiring it (a single test realm is used).
 */
@Mock
@ApplicationScoped
public class FakeClientRepository implements ClientRepositoryPort {

    public static final String PUBLIC_CLIENT_ID = "public-spa";
    public static final String CONFIDENTIAL_CLIENT_ID = "confidential-web";
    public static final String NO_CODE_CLIENT_ID = "no-code-client";

    /** Stable resolved identity for the confidential client (used by the secret verifier). */
    public static final ClientId CONFIDENTIAL_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000c0"));

    private static final ClientId PUBLIC_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000a0"));
    private static final ClientId NO_CODE_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000b0"));

    private static final Set<GrantType> CODE_GRANT = Set.of(new AuthorizationCode());
    private static final Set<GrantType> ONLY_CLIENT_CREDENTIALS = Set.of(new ClientCredentials());

    @Override
    public Uni<Client> findByClientId(RealmKey realm, String clientId) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        Client client = switch (clientId == null ? "" : clientId) {
            case PUBLIC_CLIENT_ID -> new PublicClient(PUBLIC_IDENTITY, realm, CODE_GRANT);
            case CONFIDENTIAL_CLIENT_ID -> new ConfidentialClient(
                    CONFIDENTIAL_IDENTITY, realm, CODE_GRANT, ClientAuthMethod.CLIENT_SECRET);
            case NO_CODE_CLIENT_ID -> new ConfidentialClient(
                    NO_CODE_IDENTITY, realm, ONLY_CLIENT_CREDENTIALS, ClientAuthMethod.CLIENT_SECRET);
            default -> null;
        };
        return Uni.createFrom().item(client);
    }
}
