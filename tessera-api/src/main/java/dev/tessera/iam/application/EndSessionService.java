package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.EndSessionUseCase;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort.VerifiedIdToken;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Application service for RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0).
 * Framework-free, mirroring {@link SessionService}'s shape.
 *
 * <p>The rules, in the order they are checked; the first one broken refuses the request, and a
 * refused request changes nothing:
 * <ol>
 *   <li>An {@code id_token_hint} is required. Without one the server cannot tell which client is
 *       asking or for which user, and a bare link would let any page sign a user out.</li>
 *   <li>The hint must be an ID token this realm signed ({@link IdTokenHintVerifierPort}) whose
 *       {@code iss} is this server's issuer, byte for byte, and whose realm claims name the
 *       request's realm (tenant and baseline): keysets are per tenant, so the signature alone does
 *       not tell two baselines apart. Its expiry is not checked, since the specification lets a
 *       relying party present an expired ID token, but it must have been issued within the session
 *       lifetime: an older hint cannot belong to a session that is still alive.</li>
 *   <li>The client is the hint's audience. A {@code client_id} parameter, when sent, must be that
 *       audience; a hint with several audiences needs one to say which.</li>
 *   <li>A {@code post_logout_redirect_uri}, when sent, must equal one of the client's registered
 *       post-logout redirect URIs exactly: no prefix, case or trailing-slash tolerance.</li>
 *   <li>When the browser presents a live session, its subject must be the hint's {@code sub}: an
 *       ID token for one user cannot end another user's session.</li>
 * </ol>
 *
 * <p>An accepted request ends the presented session (if any is live) and revokes every
 * refresh-token family the client holds for the hint's subject that was created no later than the
 * hint, so the relying party cannot silently obtain new tokens after its user signed out, and an old
 * hint cannot end a later sign-in. It succeeds the same way whether or not a
 * session was still live, so repeating a logout is harmless. The session ended is the one the
 * browser's cookie names; that cookie is {@code SameSite=Strict}, so a navigation from a relying
 * party on another site carries none, and such a logout revokes the refresh tokens but leaves the
 * session to expire.
 */
public final class EndSessionService implements EndSessionUseCase {

    private final ClientRepositoryPort clients;
    private final IdTokenHintVerifierPort idTokens;
    private final SessionStorePort sessions;
    private final RefreshTokenStorePort refreshTokens;
    private final String issuer;
    private final Clock clock;
    private final Duration maxHintAge;

    /**
     * @param maxHintAge how old a hint's {@code iat} may be: the session lifetime, since no session
     *                   outlives it (never {@code null}, positive)
     */
    public EndSessionService(
            ClientRepositoryPort clients,
            IdTokenHintVerifierPort idTokens,
            SessionStorePort sessions,
            RefreshTokenStorePort refreshTokens,
            String issuer,
            Clock clock,
            Duration maxHintAge) {
        if (clients == null || idTokens == null || sessions == null || refreshTokens == null) {
            throw new IllegalArgumentException("ports must not be null");
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        this.clients = clients;
        this.idTokens = idTokens;
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        if (clock == null || maxHintAge == null || maxHintAge.isZero() || maxHintAge.isNegative()) {
            throw new IllegalArgumentException("clock must not be null and maxHintAge must be positive");
        }
        this.issuer = issuer;
        this.clock = clock;
        this.maxHintAge = maxHintAge;
    }

    @Override
    public Uni<EndSessionOutcome> endSession(EndSessionCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (isBlank(command.idTokenHint())) {
            return refused("id_token_hint is required");
        }
        return idTokens.verify(command.realm(), command.idTokenHint())
                .flatMap(verified -> verified
                        .filter(token -> issuer.equals(token.issuer()) && !isBlank(token.subject())
                                && inRealm(token, command.realm()) && recent(token))
                        .map(token -> forClient(command, token))
                        .orElseGet(() -> refused("id_token_hint is not a valid ID token from this server")));
    }

    private Uni<EndSessionOutcome> forClient(EndSessionCommand command, VerifiedIdToken hint) {
        String clientId;
        if (!isBlank(command.clientId())) {
            if (!hint.audience().contains(command.clientId())) {
                return refused("client_id does not match the id_token_hint");
            }
            clientId = command.clientId();
        } else if (hint.audience().size() == 1) {
            clientId = hint.audience().get(0);
        } else {
            return refused("client_id is required when the id_token_hint names several audiences");
        }
        return clients.findByClientId(command.realm(), clientId)
                .flatMap(client -> client == null
                        ? refused("the id_token_hint names an unknown client")
                        : forRedirect(command, hint, client));
    }

    private Uni<EndSessionOutcome> forRedirect(EndSessionCommand command, VerifiedIdToken hint, Client client) {
        String redirect = command.postLogoutRedirectUri();
        if (redirect != null && !client.postLogoutRedirectUris().contains(redirect)) {
            return refused("post_logout_redirect_uri is not registered for this client");
        }
        Uni<Optional<Session>> presented = command.sessionId() == null
                ? Uni.createFrom().item(Optional.empty())
                : sessions.find(command.realm(), command.sessionId());
        return presented.flatMap(session -> {
            if (session.isPresent() && !session.get().subjectId().equals(hint.subject())) {
                return refused("id_token_hint does not match the signed-in user");
            }
            Uni<Void> ended = session.isPresent()
                    ? sessions.invalidate(command.realm(), command.sessionId())
                    : Uni.createFrom().voidItem();
            return ended
                    // iat has whole-second precision; a family minted in the hint's second is its own.
                    .flatMap(ignored -> refreshTokens.revokeFamiliesOf(command.realm(), hint.subject(), client.id(),
                            Instant.ofEpochSecond(hint.issuedAt() + 1)))
                    .map(ignored -> outcome(redirect, command.state()));
        });
    }

    private static boolean inRealm(VerifiedIdToken hint, RealmKey realm) {
        return realm.tenant().value().toString().equals(hint.realmTenant())
                && realm.baseline().value().toString().equals(hint.realmBaseline());
    }

    private boolean recent(VerifiedIdToken hint) {
        return hint.issuedAt() != null
                && !Instant.ofEpochSecond(hint.issuedAt()).isBefore(clock.instant().minus(maxHintAge));
    }

    private static EndSessionOutcome outcome(String redirect, String state) {
        if (redirect == null) {
            return new EndSessionOutcome.SignedOut();
        }
        if (isBlank(state)) {
            return new EndSessionOutcome.Redirect(redirect);
        }
        String separator = redirect.indexOf('?') >= 0 ? "&" : "?";
        return new EndSessionOutcome.Redirect(
                redirect + separator + "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8));
    }

    private static Uni<EndSessionOutcome> refused(String description) {
        return Uni.createFrom().item(new EndSessionOutcome.Refused(description));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
