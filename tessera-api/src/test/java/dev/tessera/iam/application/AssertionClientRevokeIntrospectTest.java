// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectCommand;
import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectionResult;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeCommand;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeResult;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code /revoke} and {@code /introspect} authenticate a {@code private_key_jwt} or workload-identity
 * client by its JWT assertion through the same step as the token endpoint: the key source and the
 * verifier each run once, within the request's realm, for the client's own id when it is registered
 * for an assertion method and for the sentinel otherwise. A refresh family is revoked only for the
 * client it was issued to (RFC 7009 §2.1).
 */
@DisplayName("Client assertions on /revoke and /introspect — the token endpoint's verifier, ownership kept")
class AssertionClientRevokeIntrospectTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final RealmKey OTHER = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final String GOOD = "a-valid-assertion";
    private static final ClientId KEYED = new ClientId(UUID.randomUUID());
    private static final ClientId WORKLOAD = new ClientId(UUID.randomUUID());
    private static final ClientId SECRET_CLIENT = new ClientId(UUID.randomUUID());
    private static final AssertionTrust KEYED_TRUST = new AssertionTrust("keyed", "keyed", "{\"keys\":[]}");
    private static final AssertionTrust WORKLOAD_TRUST = AssertionTrust.ofIssuer("https://platform.example", "sa-1");

    private final Map<String, Client> registry = Map.of(
            "keyed", confidential(KEYED, ClientAuthMethod.PRIVATE_KEY_JWT),
            "workload", confidential(WORKLOAD, ClientAuthMethod.WORKLOAD_IDENTITY),
            "secret-client", confidential(SECRET_CLIENT, ClientAuthMethod.CLIENT_SECRET),
            "spa", new PublicClient(new ClientId(UUID.randomUUID()), REALM, Set.of(new AuthorizationCode()), Set.of()));

    private final ClientRepositoryPort clients = (realm, clientId) ->
            Uni.createFrom().item(realm.equals(REALM) ? registry.get(clientId) : null);

    private final List<ClientId> secretChecks = new ArrayList<>();
    private final ClientSecretVerifierPort secrets = (realm, id, secret) -> {
        secretChecks.add(id);
        return Uni.createFrom().item(SECRET_CLIENT.equals(id) && "the-secret".equals(secret));
    };

    private final List<ClientId> trustLookups = new ArrayList<>();
    private final ClientKeySourcePort keys = (realm, id) -> {
        trustLookups.add(id);
        return Uni.createFrom().item(KEYED.equals(id) ? KEYED_TRUST : WORKLOAD.equals(id) ? WORKLOAD_TRUST : null);
    };

    private record Check(RealmKey realm, AssertionTrust trust, String assertion) {
    }

    private final List<Check> assertionChecks = new ArrayList<>();
    private final ClientAssertionVerifierPort assertions = (realm, trust, assertion) -> {
        assertionChecks.add(new Check(realm, trust, assertion));
        return Uni.createFrom().item(trust != null && GOOD.equals(assertion));
    };

    private final Map<FamilyId, RefreshTokenFamily> families = new HashMap<>();
    private final List<FamilyId> revoked = new ArrayList<>();
    private final RefreshTokenStorePort refreshStore = new RefreshTokenStorePort() {
        @Override
        public Uni<Void> createFamily(RefreshTokenFamily family) {
            families.put(family.id(), family);
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshConsumeOutcome> consumeAndRotate(FamilyId id, RealmKey realm, String presentedHash,
                String newTokenHash, Instant now, Duration reuseGrace, String rotationSalt) {
            return Uni.createFrom().nullItem();
        }

        @Override
        public Uni<Void> revokeFamily(FamilyId id, RealmKey realm) {
            revoked.add(id);
            families.computeIfPresent(id, (k, family) -> family.burned());
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<Void> revokeFamiliesOf(RealmKey realm, String userId, ClientId clientId, Instant createdBefore) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
            RefreshTokenFamily family = families.get(id);
            return Uni.createFrom().item(family != null && family.realm().equals(realm) ? family : null);
        }
    };

    private final AccessTokenIntrospectorPort accessTokens =
            (realm, token) -> Uni.createFrom().item(Optional.empty());

    private static ConfidentialClient confidential(ClientId id, ClientAuthMethod method) {
        return new ConfidentialClient(id, REALM, Set.of(new ClientCredentials()), method, Set.of());
    }

    /** Seeds a live refresh family issued to {@code owner} and returns its wire token. */
    private String refreshTokenOf(ClientId owner) {
        FamilyId id = new FamilyId(UUID.randomUUID());
        String secret = UUID.randomUUID().toString().replace("-", "");
        Instant now = Instant.now();
        refreshStore.createFamily(new RefreshTokenFamily(id, REALM, "user-1", owner,
                RefreshTokenCodec.sha256(secret), null, 0, false, now, now.plus(Duration.ofHours(1))));
        return RefreshTokenCodec.assemble(id, secret);
    }

    private void clearCalls() {
        secretChecks.clear();
        trustLookups.clear();
        assertionChecks.clear();
        revoked.clear();
    }

    private RevokeResult revoke(RealmKey realm, String clientId, String secret, String assertion, String token) {
        clearCalls();
        return new RevokeService(clients, secrets, keys, assertions, refreshStore)
                .revoke(new RevokeCommand(realm, token, null, clientId, secret, assertion))
                .await().indefinitely();
    }

    private IntrospectionResult introspect(RealmKey realm, String clientId, String secret, String assertion,
            String token) {
        clearCalls();
        return new IntrospectService(clients, secrets, keys, assertions, refreshStore, accessTokens,
                Clock.systemUTC())
                .introspect(new IntrospectCommand(realm, token, null, clientId, secret, assertion))
                .await().indefinitely();
    }

    @Test
    @DisplayName("a private_key_jwt client revokes its own refresh family by assertion, verified once in the request realm")
    void keyedClientRevokesItsOwnFamily() {
        String token = refreshTokenOf(KEYED);
        FamilyId family = RefreshTokenCodec.parse(token).orElseThrow().id();

        assertThat(revoke(REALM, "keyed", null, GOOD, token)).isInstanceOf(RevokeResult.Done.class);
        assertThat(revoked).containsExactly(family);
        assertThat(trustLookups).containsExactly(KEYED);
        assertThat(assertionChecks).containsExactly(new Check(REALM, KEYED_TRUST, GOOD));
        assertThat(secretChecks).isEmpty();
    }

    @Test
    @DisplayName("an assertion client cannot revoke another client's family: accepted, and a no-op (RFC 7009 §2.1)")
    void otherClientsFamilyIsKept() {
        String othersToken = refreshTokenOf(SECRET_CLIENT);

        assertThat(revoke(REALM, "keyed", null, GOOD, othersToken)).isInstanceOf(RevokeResult.Done.class);
        assertThat(revoked).isEmpty();
        assertThat(introspect(REALM, "secret-client", "the-secret", null, othersToken))
                .isInstanceOf(IntrospectionResult.Active.class);
    }

    @Test
    @DisplayName("a private_key_jwt and a workload-identity client introspect by assertion")
    void assertionClientsIntrospect() {
        String token = refreshTokenOf(KEYED);

        assertThat(introspect(REALM, "keyed", null, GOOD, token)).isInstanceOf(IntrospectionResult.Active.class);
        assertThat(assertionChecks).containsExactly(new Check(REALM, KEYED_TRUST, GOOD));
        assertThat(introspect(REALM, "workload", null, GOOD, token)).isInstanceOf(IntrospectionResult.Active.class);
        assertThat(assertionChecks).containsExactly(new Check(REALM, WORKLOAD_TRUST, GOOD));
        assertThat(secretChecks).isEmpty();

        revoke(REALM, "keyed", null, GOOD, token);
        assertThat(introspect(REALM, "keyed", null, GOOD, token)).isInstanceOf(IntrospectionResult.Inactive.class);
    }

    @Test
    @DisplayName("a refused assertion, another realm, a secret client's or a public client's assertion: invalid_client, one check each")
    void refusalsRunTheSameChecks() {
        String token = refreshTokenOf(KEYED);

        // The verifier refuses the assertion (a bad signature or claim, or a replayed jti).
        assertThat(revoke(REALM, "keyed", null, "refused", token)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(assertionChecks).containsExactly(new Check(REALM, KEYED_TRUST, "refused"));
        assertThat(introspect(REALM, "keyed", null, "refused", token))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(revoked).isEmpty();

        // Another realm does not resolve the client: the sentinel is looked up and the check fails.
        assertThat(revoke(OTHER, "keyed", null, GOOD, token)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(trustLookups).containsExactly(ClientSecretVerifierPort.unknownClient("keyed"));
        assertThat(assertionChecks).containsExactly(new Check(OTHER, null, GOOD));
        assertThat(introspect(OTHER, "keyed", null, GOOD, token))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(assertionChecks).containsExactly(new Check(OTHER, null, GOOD));

        // A client registered for a secret, and a public client, cannot use an assertion.
        for (String client : List.of("secret-client", "spa")) {
            assertThat(revoke(REALM, client, null, GOOD, token)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
            assertThat(assertionChecks).containsExactly(new Check(REALM, null, GOOD));
            assertThat(introspect(REALM, client, null, GOOD, token))
                    .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
            assertThat(secretChecks).isEmpty();
        }
        assertThat(revoked).isEmpty();
    }

    @Test
    @DisplayName("an assertion client presenting a secret instead is refused (one method per client)")
    void assertionClientCannotUseASecret() {
        String token = refreshTokenOf(KEYED);

        assertThat(revoke(REALM, "keyed", "the-secret", null, token))
                .isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(secretChecks).containsExactly(ClientSecretVerifierPort.unknownClient("keyed"));
        assertThat(assertionChecks).isEmpty();
        assertThat(introspect(REALM, "keyed", "the-secret", null, token))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(revoked).isEmpty();
    }
}
