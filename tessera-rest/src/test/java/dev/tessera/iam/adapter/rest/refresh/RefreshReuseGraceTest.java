package dev.tessera.iam.adapter.rest.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import dev.tessera.iam.domain.client.PublicClient;
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
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The refresh grant's optional reuse grace, against the real in-memory store: a client that
 * presents one refresh token twice at once (parallel requests of one browser session served by
 * different gateway instances) must not burn the family, and both requests must end with the same
 * live token; outside the grace the second presentation is a replay as before.
 */
@DisplayName("RefreshService — reuse grace for concurrent presentations")
class RefreshReuseGraceTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final Duration GRACE = Duration.ofSeconds(5);
    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes();
    private static final RealmKey REALM =
            new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
    private static final ClientId CLIENT_ID = new ClientId(UUID.randomUUID());
    private static final String CLIENT_WIRE = "gateway";
    private static final String USER = UUID.randomUUID().toString();
    private static final String SECRET = "client-secret";
    private static final Set<GrantType> CODE_AND_REFRESH =
            Set.of(new AuthorizationCode(), new RefreshToken());

    private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();
    private final MutableClock clock = new MutableClock(T0);

    private static final ClientId PUBLIC_ID = new ClientId(UUID.randomUUID());
    private static final String PUBLIC_WIRE = "spa";

    private final ClientRepositoryPort clients = (realm, clientId) -> Uni.createFrom().item(
            CLIENT_WIRE.equals(clientId)
                    ? new ConfidentialClient(CLIENT_ID, realm, CODE_AND_REFRESH,
                            ClientAuthMethod.CLIENT_SECRET, Set.of("https://c/cb"))
                    : PUBLIC_WIRE.equals(clientId)
                            ? new PublicClient(PUBLIC_ID, realm, CODE_AND_REFRESH, Set.of("https://c/cb"))
                            : (Client) null);
    /** The claim sets signed as ID tokens ({@code typ JWT}), in order. */
    private final List<ClaimSet> idTokens = new ArrayList<>();
    private final ClientSecretVerifierPort verifier =
            (realm, clientId, secret) -> Uni.createFrom().item(SECRET.equals(secret));
    private final TokenSignerPort signer = new TokenSignerPort() {
        @Override
        public Uni<String> sign(RealmKey realm, String typ, ClaimSet claims) {
            if ("JWT".equals(typ)) {
                idTokens.add(claims);
            }
            return Uni.createFrom().item("signed." + typ);
        }
    };
    private final OpaqueIdentifierPort ids = new OpaqueIdentifierPort() {
        @Override public String newAuthorizationCode() { return "code"; }
        @Override public String newTokenId() { return "jti-" + UUID.randomUUID(); }
        @Override public String newRefreshToken() { return "random-" + UUID.randomUUID(); }
        @Override public UUID newFamilyId() { return UUID.randomUUID(); }
    };

    private RefreshService service(Duration grace, byte[] key) {
        return new RefreshService(clients, verifier, signer, ids, store, store, clock,
                "https://issuer.test", Duration.ofMinutes(5), Duration.ofMinutes(5), true, grace, key);
    }

    private FamilyId fid;

    private String seedFamily() {
        return seedFamily(CLIENT_ID, Set.of("offline_access"));
    }

    private String seedFamily(ClientId owner, Set<String> scopes) {
        fid = new FamilyId(UUID.randomUUID());
        String secret = "seed-" + UUID.randomUUID();
        store.createFamily(new RefreshTokenFamily(
                fid, REALM, USER, owner,
                RefreshTokenCodec.sha256(secret), null, 0, false, T0, T0.plusSeconds(3600), scopes))
                .await().indefinitely();
        return RefreshTokenCodec.assemble(fid, secret);
    }

    private TokenResult redeem(RefreshService service, String wire) {
        return service.redeem(new RefreshCommand(REALM, wire, CLIENT_WIRE, SECRET, null))
                .await().indefinitely();
    }

    private TokenResult redeemAsPublic(RefreshService service, String wire) {
        return service.redeem(new RefreshCommand(REALM, wire, PUBLIC_WIRE, null, null))
                .await().indefinitely();
    }

    private RefreshTokenFamily family() {
        return store.find(fid, REALM).await().indefinitely();
    }

    @Test
    @DisplayName("within the grace, the superseded token receives the same successor; nothing is burned")
    void withinGraceSameSuccessor() {
        RefreshService service = service(GRACE, KEY);
        String wire = seedFamily();

        TokenResult first = redeem(service, wire);
        clock.advance(Duration.ofSeconds(2));
        TokenResult second = redeem(service, wire);

        assertThat(first).isInstanceOf(TokenResult.Issued.class);
        assertThat(second).as("the concurrent presentation").isInstanceOf(TokenResult.Issued.class);
        String successor = ((TokenResult.Issued) first).refreshToken();
        assertThat(((TokenResult.Issued) second).refreshToken())
                .as("both requests end with the same live token").isEqualTo(successor);
        assertThat(family().reused()).isFalse();
        assertThat(family().generation()).as("rotated once, not twice").isEqualTo(1);

        // The shared successor keeps rotating normally.
        clock.advance(Duration.ofMinutes(5));
        TokenResult next = redeem(service, successor);
        assertThat(next).isInstanceOf(TokenResult.Issued.class);
        assertThat(family().generation()).isEqualTo(2);
    }

    @Test
    @DisplayName("the key plus everything the store holds cannot reproduce the live token; the predecessor is needed")
    void keyPlusStoreDoesNotYieldTheSuccessor() {
        RefreshService service = service(GRACE, KEY);
        String wire = seedFamily();
        String predecessorSecret = RefreshTokenCodec.parse(wire).orElseThrow().secret();
        redeem(service, wire);

        RefreshTokenFamily row = family();
        String live = row.currentTokenHash();
        // Every value the row holds, fed to the derivation with the key, misses the live token.
        for (String fromRow : List.of(row.previousTokenHash(), row.currentTokenHash(), row.rotationSalt())) {
            String guess = RefreshTokenCodec.successorSecret(KEY, fid, fromRow, row.rotationSalt());
            assertThat(RefreshTokenCodec.sha256(guess)).as("derived from a stored value").isNotEqualTo(live);
        }
        // Only the predecessor token itself, with the key and the stored salt, reproduces it.
        assertThat(RefreshTokenCodec.sha256(
                RefreshTokenCodec.successorSecret(KEY, fid, predecessorSecret, row.rotationSalt())))
                .isEqualTo(live);
    }

    @Test
    @DisplayName("after the grace, the superseded token is a replay that revokes the family")
    void afterGraceReplay() {
        RefreshService service = service(GRACE, KEY);
        String wire = seedFamily();
        String successor = ((TokenResult.Issued) redeem(service, wire)).refreshToken();

        clock.advance(GRACE.plusSeconds(1));
        TokenResult late = redeem(service, wire);

        assertThat(late).isInstanceOf(TokenResult.Failed.class);
        assertThat(((TokenResult.Failed) late).error()).isEqualTo(AuthorizationError.INVALID_GRANT);
        assertThat(family().reused()).isTrue();
        assertThat(redeem(service, successor)).as("the whole family is revoked")
                .isInstanceOf(TokenResult.Failed.class);
    }

    @Test
    @DisplayName("without a grace (the default), a second presentation revokes the family at once")
    void noGraceIsStrict() {
        RefreshService service = service(Duration.ZERO, null);
        String wire = seedFamily();
        redeem(service, wire);
        TokenResult second = redeem(service, wire);

        assertThat(second).isInstanceOf(TokenResult.Failed.class);
        assertThat(family().reused()).isTrue();
    }

    @Test
    @DisplayName("a public client gets no grace: a second presentation inside the window still revokes")
    void publicClientStaysStrict() {
        RefreshService service = service(GRACE, KEY);
        String wire = seedFamily(PUBLIC_ID, Set.of("offline_access"));

        assertThat(redeemAsPublic(service, wire)).isInstanceOf(TokenResult.Issued.class);
        clock.advance(Duration.ofSeconds(1));
        TokenResult second = redeemAsPublic(service, wire);

        assertThat(second).isInstanceOf(TokenResult.Failed.class);
        assertThat(family().reused()).as("burned inside the window").isTrue();
        assertThat(family().rotationSalt()).as("a public client's successor is random").isNull();
    }

    @Test
    @DisplayName("under openid a refresh re-issues an ID token for the same subject and client, without a nonce")
    void refreshReissuesIdTokenUnderOpenid() {
        RefreshService service = service(Duration.ZERO, null);
        String wire = seedFamily(CLIENT_ID, Set.of("openid", "profile", "offline_access"));

        TokenResult.Issued issued = (TokenResult.Issued) redeem(service, wire);

        assertThat(issued.idToken()).isEqualTo("signed.JWT");
        assertThat(idTokens).hasSize(1);
        ClaimSet id = idTokens.get(0);
        assertThat(id.claim("sub")).contains(USER);
        assertThat(id.claim("aud")).contains(CLIENT_WIRE);
        assertThat(id.claim("iss")).contains("https://issuer.test");
        assertThat(id.claim("nonce")).as("OIDC Core 12.2: no nonce on a refreshed ID token").isEmpty();
        assertThat(id.claim("realm_tenant")).as("profile still asserts the realm")
                .contains(REALM.tenant().value().toString());
    }

    @Test
    @DisplayName("without openid in the original grant, a refresh returns no ID token")
    void noIdTokenWithoutOpenid() {
        RefreshService service = service(Duration.ZERO, null);
        String wire = seedFamily(CLIENT_ID, Set.of("offline_access"));

        TokenResult.Issued issued = (TokenResult.Issued) redeem(service, wire);

        assertThat(issued.idToken()).isNull();
        assertThat(idTokens).isEmpty();
    }

    @Test
    @DisplayName("a positive grace without a successor key is refused at construction")
    void graceNeedsAKey() {
        assertThatThrownBy(() -> service(GRACE, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service(GRACE, new byte[16])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service(Duration.ofSeconds(-1), KEY))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** A clock the test moves forward. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
