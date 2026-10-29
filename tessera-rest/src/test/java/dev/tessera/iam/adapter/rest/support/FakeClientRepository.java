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
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.LinkedHashSet;
import java.util.List;
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
    /** A public client additionally permitted the refresh-token grant (for the refresh flow). */
    public static final String REFRESH_CLIENT_ID = "refresh-spa";

    /**
     * A {@code client_credentials} service client, registered only in {@link #MACHINE_TENANT}: under
     * any other tenant it does not exist, as under the real registry's row-level security.
     */
    public static final String MACHINE_CLIENT_ID = "machine-service";
    public static final String MACHINE_TENANT = "6f1c2a64-5d1e-4f0a-9a43-0c2b8e7d4a11";
    public static final ClientId MACHINE_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000e0"));
    public static final Set<String> MACHINE_SCOPES = new LinkedHashSet<>(List.of("orders.read", "orders.write"));
    public static final Set<String> MACHINE_AUDIENCES =
            new LinkedHashSet<>(List.of("https://orders.example", "https://billing.example"));
    public static final List<String> MACHINE_ROLES = List.of("ops", "reader");

    /** A {@code client_credentials} client of {@link #MACHINE_TENANT} that authenticates by {@code private_key_jwt}. */
    public static final String KEYED_CLIENT_ID = "keyed-service";
    public static final ClientId KEYED_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000f0"));

    /** Stable resolved identity for the confidential client (used by the secret verifier). */
    public static final ClientId CONFIDENTIAL_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000c0"));

    private static final ClientId PUBLIC_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000a0"));
    private static final ClientId NO_CODE_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000b0"));
    private static final ClientId REFRESH_IDENTITY =
            new ClientId(UUID.fromString("00000000-0000-0000-0000-0000000000d0"));

    private static final Set<GrantType> CODE_GRANT = Set.of(new AuthorizationCode());
    private static final Set<GrantType> CODE_AND_REFRESH =
            Set.of(new AuthorizationCode(), new RefreshToken());
    private static final Set<GrantType> ONLY_CLIENT_CREDENTIALS = Set.of(new ClientCredentials());

    /** The redirect URI the flow tests use; registered for every fake client. */
    public static final String REDIRECT_URI = "https://client.example/callback";
    private static final Set<String> REDIRECTS = Set.of(REDIRECT_URI);

    /** The post-logout redirect URI registered for the two public clients (and no other URI). */
    public static final String POST_LOGOUT_REDIRECT_URI = "https://client.example/signed-out";
    private static final Set<String> POST_LOGOUT_REDIRECTS = Set.of(POST_LOGOUT_REDIRECT_URI);

    @Override
    public Uni<Client> findByClientId(RealmKey realm, String clientId) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        Client client = switch (clientId == null ? "" : clientId) {
            case PUBLIC_CLIENT_ID -> new PublicClient(
                    PUBLIC_IDENTITY, realm, CODE_GRANT, REDIRECTS, POST_LOGOUT_REDIRECTS);
            case CONFIDENTIAL_CLIENT_ID -> new ConfidentialClient(
                    CONFIDENTIAL_IDENTITY, realm, CODE_GRANT, ClientAuthMethod.CLIENT_SECRET, REDIRECTS);
            case NO_CODE_CLIENT_ID -> new ConfidentialClient(
                    NO_CODE_IDENTITY, realm, ONLY_CLIENT_CREDENTIALS, ClientAuthMethod.CLIENT_SECRET, REDIRECTS);
            case REFRESH_CLIENT_ID -> new PublicClient(
                    REFRESH_IDENTITY, realm, CODE_AND_REFRESH, REDIRECTS, POST_LOGOUT_REDIRECTS);
            case MACHINE_CLIENT_ID -> MACHINE_TENANT.equals(realm.tenant().value().toString())
                    ? new ConfidentialClient(MACHINE_IDENTITY, realm, ONLY_CLIENT_CREDENTIALS,
                            ClientAuthMethod.CLIENT_SECRET, Set.of(), MACHINE_SCOPES, MACHINE_AUDIENCES, MACHINE_ROLES)
                    : null;
            case KEYED_CLIENT_ID -> MACHINE_TENANT.equals(realm.tenant().value().toString())
                    ? new ConfidentialClient(KEYED_IDENTITY, realm, ONLY_CLIENT_CREDENTIALS,
                            ClientAuthMethod.PRIVATE_KEY_JWT, Set.of(), MACHINE_SCOPES, MACHINE_AUDIENCES, MACHINE_ROLES)
                    : null;
            default -> null;
        };
        return Uni.createFrom().item(client);
    }
}
