package dev.tessera.iam.adapter.rest.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.port.in.RefreshUseCase.RefreshCommand;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.token.ClaimSet;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit coverage for {@link RefreshService} on the paths the public-client HTTP flow test does not
 * exercise: confidential-client authentication ({@code invalid_client}) and the fail-closed issuance
 * invariant (a tenant mismatch mints nothing — the signer is never called). Uses the real in-memory
 * store with hand-rolled port fakes, mirroring {@code AuthorizationServiceTest}.
 */
@DisplayName("RefreshService — client auth + fail-closed issuance")
class RefreshServiceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final RealmKey REALM_A =
            new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
    private static final ClientId CONF_ID = new ClientId(UUID.randomUUID());
    private static final String CONF_WIRE = "conf-web";
    private static final String CORRECT_SECRET = "correct-secret";
    private static final Set<GrantType> CODE_AND_REFRESH =
            Set.of(new AuthorizationCode(), new RefreshToken());

    private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    private final AtomicInteger signerCalls = new AtomicInteger();

    private final ClientRepositoryPort clients = (realm, clientId) -> Uni.createFrom().item(
            CONF_WIRE.equals(clientId)
                    ? new ConfidentialClient(CONF_ID, realm, CODE_AND_REFRESH,
                            ClientAuthMethod.CLIENT_SECRET, Set.of("https://c/cb"))
                    : (Client) null);

    private final ClientSecretVerifierPort verifier =
            (realm, clientId, secret) -> Uni.createFrom().item(CORRECT_SECRET.equals(secret));

    private final TokenSignerPort signer = new TokenSignerPort() {
        @Override
        public Uni<String> sign(RealmKey realm, String typ, ClaimSet claims) {
            signerCalls.incrementAndGet();
            return Uni.createFrom().item("signed.jwt.value");
        }
    };

    private final OpaqueIdentifierPort ids = new OpaqueIdentifierPort() {
        @Override public String newAuthorizationCode() { return "code"; }
        @Override public String newTokenId() { return "jti"; }
        @Override public String newRefreshToken() { return "new-secret-" + UUID.randomUUID(); }
        @Override public UUID newFamilyId() { return UUID.randomUUID(); }
    };

    private RefreshService service() {
        return new RefreshService(clients, verifier, signer, ids, store, store,
                Clock.fixed(T0, ZoneOffset.UTC), "https://issuer.test", Duration.ofMinutes(5), true);
    }

    /** Seeds a live family owned by the confidential client in realm A, returns its wire token. */
    private String seedFamily() {
        FamilyId fid = new FamilyId(UUID.randomUUID());
        String secret = "seed-secret-" + UUID.randomUUID();
        RefreshTokenFamily fam = new RefreshTokenFamily(
                fid, REALM_A, UUID.randomUUID().toString(), CONF_ID,
                RefreshTokenCodec.sha256(secret), null, 0, false, T0, T0.plusSeconds(3600));
        store.createFamily(fam).await().indefinitely();
        return RefreshTokenCodec.assemble(fid, secret);
    }

    @Test
    @DisplayName("a confidential client presenting a wrong secret is invalid_client; nothing is issued")
    void wrongSecretIsInvalidClient() {
        String wire = seedFamily();
        TokenResult result = service()
                .redeem(new RefreshCommand(REALM_A, wire, CONF_WIRE, "WRONG", null))
                .await().indefinitely();
        assertThat(result).isInstanceOf(TokenResult.Failed.class);
        assertThat(((TokenResult.Failed) result).error()).isEqualTo(AuthorizationError.INVALID_CLIENT);
        assertThat(signerCalls).hasValue(0);
    }

    @Test
    @DisplayName("a tenant mismatch mints nothing — the signer is never called (fail-closed issuance)")
    void tenantMismatchIssuesNothing() {
        String wire = seedFamily();
        RealmKey otherRealm =
                new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
        // Correct secret, but the request tenant differs from the family's authoritative realm.
        TokenResult result = service()
                .redeem(new RefreshCommand(otherRealm, wire, CONF_WIRE, CORRECT_SECRET, null))
                .await().indefinitely();
        assertThat(result).isInstanceOf(TokenResult.Failed.class);
        assertThat(((TokenResult.Failed) result).error()).isEqualTo(AuthorizationError.INVALID_GRANT);
        assertThat(signerCalls).as("no token minted on tenant mismatch").hasValue(0);
    }

    @Test
    @DisplayName("the correct secret in the family's own tenant rotates and issues tokens")
    void happyRotate() {
        String wire = seedFamily();
        TokenResult result = service()
                .redeem(new RefreshCommand(REALM_A, wire, CONF_WIRE, CORRECT_SECRET, null))
                .await().indefinitely();
        assertThat(result).isInstanceOf(TokenResult.Issued.class);
        TokenResult.Issued issued = (TokenResult.Issued) result;
        assertThat(issued.accessToken()).isEqualTo("signed.jwt.value");
        assertThat(issued.refreshToken()).isNotBlank().isNotEqualTo(wire);
        assertThat(signerCalls).hasValue(1);
    }

    @Test
    @DisplayName("a malformed / unknown refresh token is invalid_grant")
    void unknownTokenIsInvalidGrant() {
        TokenResult result = service()
                .redeem(new RefreshCommand(REALM_A, "not-a-real-token", CONF_WIRE, CORRECT_SECRET, null))
                .await().indefinitely();
        assertThat(result).isInstanceOf(TokenResult.Failed.class);
        assertThat(((TokenResult.Failed) result).error()).isEqualTo(AuthorizationError.INVALID_GRANT);
        assertThat(signerCalls).hasValue(0);
    }
}
