package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.EndSessionUseCase.EndSessionCommand;
import dev.tessera.iam.application.port.in.EndSessionUseCase.EndSessionOutcome;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort.VerifiedIdToken;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("EndSessionService — RP-initiated logout rules; a refusal changes nothing")
class EndSessionServiceTest {

    private static final String ISSUER = "https://issuer.example";
    private static final RealmKey REALM =
            new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
    private static final String CLIENT = "spa";
    private static final ClientId CLIENT_ID = ClientId.generate();
    private static final String SIGNED_OUT = "https://rp.example/signed-out";
    private static final String USER = UUID.randomUUID().toString();
    private static final String HINT = "hint";
    private static final Instant NOW = Instant.parse("2026-10-29T12:00:00Z");
    private static final Duration SESSION_TTL = Duration.ofHours(8);
    private static final long IAT = NOW.minusSeconds(60).getEpochSecond();
    private static final String TENANT = REALM.tenant().value().toString();
    private static final String BASELINE = REALM.baseline().value().toString();

    private final Map<String, VerifiedIdToken> hints = new HashMap<>();
    private final Map<SessionId, Session> live = new HashMap<>();
    private final List<SessionId> invalidated = new ArrayList<>();
    private final List<String> revoked = new ArrayList<>();

    private final EndSessionService service = new EndSessionService(
            clients(), (realm, token) -> Uni.createFrom().item(Optional.ofNullable(hints.get(token))),
            sessions(), refreshTokens(), ISSUER, Clock.fixed(NOW, ZoneOffset.UTC), SESSION_TTL);

    /** A hint as the server issues one: this issuer, this realm, a minute old. */
    private static VerifiedIdToken hint(String issuer, String subject, List<String> audience) {
        return new VerifiedIdToken(issuer, subject, audience, IAT, TENANT, BASELINE);
    }

    private EndSessionOutcome run(String hint, String clientId, String redirect, String state, SessionId session) {
        return service.endSession(new EndSessionCommand(REALM, hint, clientId, redirect, state, session))
                .await().indefinitely();
    }

    private SessionId signedIn(String subject) {
        SessionId id = SessionId.generate();
        live.put(id, new Session(REALM, id, subject, Instant.now(), Instant.now().plus(Duration.ofHours(1))));
        return id;
    }

    private void assertRefusedAndNothingChanged(EndSessionOutcome outcome) {
        assertThat(outcome).isInstanceOf(EndSessionOutcome.Refused.class);
        assertThat(invalidated).isEmpty();
        assertThat(revoked).isEmpty();
    }

    @Test
    @DisplayName("an accepted request ends the session, revokes the client's families, redirects with state")
    void acceptedEndsSessionAndRevokes() {
        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT)));
        SessionId session = signedIn(USER);

        EndSessionOutcome outcome = run(HINT, null, SIGNED_OUT, "a b&c", session);

        assertThat(outcome).isEqualTo(new EndSessionOutcome.Redirect(SIGNED_OUT + "?state=a+b%26c"));
        assertThat(invalidated).containsExactly(session);
        assertThat(revoked).containsExactly(USER + "|" + CLIENT_ID + "|" + Instant.ofEpochSecond(IAT + 1));
    }

    @Test
    @DisplayName("no live session still revokes, and no redirect asked is SignedOut")
    void acceptedWithoutSession() {
        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT)));

        assertThat(run(HINT, CLIENT, null, "ignored", SessionId.generate()))
                .isInstanceOf(EndSessionOutcome.SignedOut.class);
        assertThat(invalidated).isEmpty();
        assertThat(revoked).containsExactly(USER + "|" + CLIENT_ID + "|" + Instant.ofEpochSecond(IAT + 1));
    }

    @Test
    @DisplayName("a hint older than the session lifetime, or without iat, is refused")
    void hintAgeBounded() {
        SessionId session = signedIn(USER);
        long tooOld = NOW.minus(SESSION_TTL).minusSeconds(1).getEpochSecond();
        hints.put(HINT, new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), tooOld, TENANT, BASELINE));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
        hints.put(HINT, new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), null, TENANT, BASELINE));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));

        long justInside = NOW.minus(SESSION_TTL).getEpochSecond();
        hints.put(HINT, new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), justInside, TENANT, BASELINE));
        assertThat(run(HINT, null, SIGNED_OUT, null, session)).isInstanceOf(EndSessionOutcome.Redirect.class);
    }

    @Test
    @DisplayName("a hint from another baseline or tenant, or without realm claims, is refused")
    void hintRealmChecked() {
        SessionId session = signedIn(USER);
        for (VerifiedIdToken foreign : List.of(
                new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), IAT, TENANT, UUID.randomUUID().toString()),
                new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), IAT, UUID.randomUUID().toString(), BASELINE),
                new VerifiedIdToken(ISSUER, USER, List.of(CLIENT), IAT, null, null))) {
            hints.put(HINT, foreign);
            assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
        }
    }

    @Test
    @DisplayName("a missing or unverifiable hint is refused")
    void hintRequiredAndVerified() {
        SessionId session = signedIn(USER);
        assertRefusedAndNothingChanged(run(null, CLIENT, SIGNED_OUT, null, session));
        assertRefusedAndNothingChanged(run(" ", CLIENT, SIGNED_OUT, null, session));
        assertRefusedAndNothingChanged(run("unknown", CLIENT, SIGNED_OUT, null, session));
    }

    @Test
    @DisplayName("a hint from another issuer, or without a subject, is refused")
    void issuerAndSubjectChecked() {
        SessionId session = signedIn(USER);
        hints.put(HINT, hint(ISSUER + "/", USER, List.of(CLIENT)));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
        hints.put(HINT, hint(ISSUER, null, List.of(CLIENT)));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
    }

    @Test
    @DisplayName("client_id must be the hint's audience; several audiences need one; an unknown client is refused")
    void clientResolution() {
        SessionId session = signedIn(USER);
        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT)));
        assertRefusedAndNothingChanged(run(HINT, "other", SIGNED_OUT, null, session));

        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT, "other")));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));

        hints.put(HINT, hint(ISSUER, USER, List.of("unknown-client")));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
    }

    @Test
    @DisplayName("the redirect must equal a registered post-logout URI exactly")
    void redirectExactMatch() {
        SessionId session = signedIn(USER);
        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT)));
        for (String uri : List.of(SIGNED_OUT + "/", SIGNED_OUT + "?x=1", "https://RP.example/signed-out",
                "https://rp.example/signed-out-not", "https://rp.example/callback", "")) {
            assertRefusedAndNothingChanged(run(HINT, null, uri, null, session));
        }
    }

    @Test
    @DisplayName("a hint for another user than the session's is refused")
    void hintMustMatchSession() {
        SessionId session = signedIn(UUID.randomUUID().toString());
        hints.put(HINT, hint(ISSUER, USER, List.of(CLIENT)));
        assertRefusedAndNothingChanged(run(HINT, null, SIGNED_OUT, null, session));
        assertThat(live).containsKey(session);
    }

    private ClientRepositoryPort clients() {
        Client spa = new PublicClient(CLIENT_ID, REALM, Set.of(new AuthorizationCode()),
                Set.of("https://rp.example/callback"), Set.of(SIGNED_OUT));
        return (realm, clientId) -> Uni.createFrom().item(CLIENT.equals(clientId) ? spa : null);
    }

    private SessionStorePort sessions() {
        return new SessionStorePort() {
            @Override
            public Uni<Session> create(RealmKey realm, String subjectId, Duration ttl) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Uni<Optional<Session>> find(RealmKey realm, SessionId id) {
                return Uni.createFrom().item(Optional.ofNullable(live.get(id)));
            }

            @Override
            public Uni<Void> invalidate(RealmKey realm, SessionId id) {
                invalidated.add(id);
                live.remove(id);
                return Uni.createFrom().voidItem();
            }
        };
    }

    private RefreshTokenStorePort refreshTokens() {
        return new RefreshTokenStorePort() {
            @Override
            public Uni<Void> createFamily(RefreshTokenFamily family) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Uni<RefreshConsumeOutcome> consumeAndRotate(FamilyId id, RealmKey realm, String presentedHash,
                    String newTokenHash, Instant now, Duration reuseGrace, String rotationSalt) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Uni<Void> revokeFamily(FamilyId id, RealmKey realm) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Uni<Void> revokeFamiliesOf(
                    RealmKey realm, String userId, ClientId clientId, Instant createdBefore) {
                revoked.add(userId + "|" + clientId + "|" + createdBefore);
                return Uni.createFrom().voidItem();
            }

            @Override
            public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
