package dev.tessera.iam.application.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.RefreshService;
import dev.tessera.iam.application.port.in.RefreshUseCase.RefreshCommand;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshReuseDetection;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.text.MessageFormat;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * A replay that revokes a refresh-token family is logged once, naming the family, tenant, baseline
 * and client and carrying no token material, so a forced sign-out can be diagnosed. Before, the
 * revocation was silent.
 */
@DisplayName("RefreshService — a replay revocation is logged once")
class RefreshReplayLogTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final RealmKey REALM =
            new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(UUID.randomUUID()));
    private static final ClientId CLIENT_ID = new ClientId(UUID.randomUUID());

    private final Logger logger = Logger.getLogger(RefreshService.class.getName());
    private final List<LogRecord> records = new ArrayList<>();
    private final Handler capture = new Handler() {
        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    @BeforeEach
    void attach() {
        logger.addHandler(capture);
    }

    @AfterEach
    void detach() {
        logger.removeHandler(capture);
    }

    @Test
    @DisplayName("presenting a superseded token logs one line with ids and no secret")
    void replayIsLoggedOnce() {
        FamilyStore store = new FamilyStore();
        FamilyId fid = new FamilyId(UUID.randomUUID());
        String secret = "seed-secret-" + UUID.randomUUID();
        store.family = new RefreshTokenFamily(fid, REALM, UUID.randomUUID().toString(), CLIENT_ID,
                RefreshTokenCodec.sha256(secret), null, 0, false, T0, T0.plusSeconds(3600));
        RefreshService service = new RefreshService(
                (realm, clientId) -> Uni.createFrom().item(new ConfidentialClient(CLIENT_ID, realm,
                        Set.of(new AuthorizationCode(), new RefreshToken()),
                        ClientAuthMethod.CLIENT_SECRET, Set.of("https://c/cb"))),
                (realm, clientId, presented) -> Uni.createFrom().item(Boolean.TRUE),
                (realm, typ, claims) -> Uni.createFrom().item("signed.jwt"),
                new OpaqueIdentifierPort() {
                    @Override public String newAuthorizationCode() { return "code"; }
                    @Override public String newTokenId() { return "jti"; }
                    @Override public String newRefreshToken() { return "next-" + UUID.randomUUID(); }
                    @Override public UUID newFamilyId() { return UUID.randomUUID(); }
                    @Override public String newSignInSecret() { return UUID.randomUUID().toString(); }
                },
                store,
                id -> Uni.createFrom().item(Optional.of(REALM)),
                Clock.fixed(T0, ZoneOffset.UTC), "https://issuer.test", Duration.ofMinutes(5), true);
        String wire = RefreshTokenCodec.assemble(fid, secret);
        RefreshCommand command = new RefreshCommand(REALM, wire, "gateway", "client-secret", null);

        assertThat(service.redeem(command).await().indefinitely()).isInstanceOf(TokenResult.Issued.class);
        assertThat(records).as("a normal rotation logs nothing").isEmpty();

        assertThat(service.redeem(command).await().indefinitely()).isInstanceOf(TokenResult.Failed.class);

        assertThat(records).hasSize(1);
        assertThat(records.get(0).getLevel()).isEqualTo(Level.WARNING);
        String line = MessageFormat.format(records.get(0).getMessage(), records.get(0).getParameters());
        assertThat(line)
                .contains(fid.value().toString())
                .contains(REALM.tenant().value().toString())
                .contains(REALM.baseline().value().toString())
                .contains(CLIENT_ID.value().toString())
                .doesNotContain(secret);

        // Presenting it again finds the family already revoked: no second warning.
        assertThat(service.redeem(command).await().indefinitely()).isInstanceOf(TokenResult.Failed.class);
        assertThat(records.stream().filter(r -> r.getLevel() == Level.WARNING))
                .as("one warning per revocation").hasSize(1);
    }

    /** A one-family store with the same rotate/replay rule as the real adapters. */
    private static final class FamilyStore implements RefreshTokenStorePort {
        RefreshTokenFamily family;

        @Override
        public Uni<Void> createFamily(RefreshTokenFamily created) {
            family = created;
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshConsumeOutcome> consumeAndRotate(FamilyId id, RealmKey realm,
                String presentedHash, String newTokenHash, Instant now, Duration reuseGrace,
                String rotationSalt) {
            RefreshDecision decision = RefreshReuseDetection.classify(family, presentedHash, now, reuseGrace);
            if (decision instanceof RefreshDecision.Rotate) {
                family = family.rotatedTo(newTokenHash, now, rotationSalt);
            } else if (decision instanceof RefreshDecision.Replay) {
                family = family.burned();
            }
            return Uni.createFrom().item(new RefreshConsumeOutcome(decision, family));
        }

        @Override
        public Uni<Void> revokeFamily(FamilyId id, RealmKey realm) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<Void> revokeFamiliesOf(RealmKey realm, String userId, ClientId clientId) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
            return Uni.createFrom().item(family);
        }
    }
}
