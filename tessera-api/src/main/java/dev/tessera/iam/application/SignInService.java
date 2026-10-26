// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.AuthorizeUseCase;
import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.in.LoginUseCase.LoginResult;
import dev.tessera.iam.application.port.in.SignInUseCase;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Application service for the hosted sign-in page. Framework-free, wired by the adapter like
 * the other services.
 *
 * <p>It adds no second path to an authorization code: once the user has signed in it hands the
 * parked request to {@link AuthorizeUseCase}, which validates the client again and mints the
 * code exactly as it does for a request that arrived signed in.
 *
 * <p>The order of {@link #submit} is part of its security. The transaction, its browser binding
 * and the synchronizer token are checked before the credential, so a post that did not come
 * from the browser holding the form never reaches password verification. The transaction is
 * consumed only after the credential verifies, so a mistyped password can be retried, and
 * consumed atomically, so one sign-in answers the request at most once.
 */
public final class SignInService implements SignInUseCase {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final ClientRepositoryPort clients;
    private final AuthorizeUseCase authorize;
    private final LoginUseCase login;
    private final PendingAuthorizationStorePort pending;
    private final OpaqueIdentifierPort identifiers;
    private final Clock clock;
    private final Duration lifetime;

    public SignInService(
            ClientRepositoryPort clients,
            AuthorizeUseCase authorize,
            LoginUseCase login,
            PendingAuthorizationStorePort pending,
            OpaqueIdentifierPort identifiers,
            Clock clock,
            Duration lifetime) {
        this.clients = requireNonNull(clients, "clients");
        this.authorize = requireNonNull(authorize, "authorize");
        this.login = requireNonNull(login, "login");
        this.pending = requireNonNull(pending, "pending");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.clock = requireNonNull(clock, "clock");
        this.lifetime = requireNonNull(lifetime, "lifetime");
        if (lifetime.isZero() || lifetime.isNegative()) {
            throw new IllegalArgumentException("lifetime must be positive");
        }
    }

    @Override
    public Uni<BeginResult> begin(AuthorizationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return clients.findByClientId(request.realm(), request.clientId())
                .flatMap(client -> {
                    AuthorizeResult.Failed refusal = ClientRequestCheck.refusal(client, request);
                    if (refusal != null) {
                        return Uni.createFrom().item(
                                (BeginResult) new BeginResult.Refused(refusal.error(), refusal.description()));
                    }
                    return park(request);
                });
    }

    private Uni<BeginResult> park(AuthorizationRequest request) {
        Instant now = clock.instant();
        String binding = identifiers.newSignInSecret();
        PendingAuthorization entry = new PendingAuthorization(
                identifiers.newSignInSecret(),
                request,
                identifiers.newSignInSecret(),
                hash(binding),
                now,
                now.plus(lifetime));
        return pending.store(entry)
                .replaceWith(new BeginResult.Started(entry.transactionId(), binding, lifetime));
    }

    @Override
    public Uni<FormResult> show(RealmKey realm, String transactionId, String binding) {
        if (realm == null || isBlank(transactionId) || isBlank(binding)) {
            return Uni.createFrom().item(new FormResult.Unavailable());
        }
        return pending.find(realm, transactionId)
                .map(entry -> entry != null && bound(entry, binding) && !entry.isExpired(clock.instant())
                        ? new FormResult.Shown(form(entry))
                        : new FormResult.Unavailable());
    }

    @Override
    public Uni<SubmitResult> submit(Submission submission) {
        if (submission == null) {
            throw new IllegalArgumentException("submission must not be null");
        }
        RealmKey realm = submission.realm();
        if (realm == null || isBlank(submission.transactionId()) || isBlank(submission.binding())
                || isBlank(submission.csrfToken())) {
            return unavailable();
        }
        return pending.find(realm, submission.transactionId()).flatMap(entry -> {
            if (entry == null
                    || entry.isExpired(clock.instant())
                    || !bound(entry, submission.binding())
                    || !sameSecret(entry.csrfToken(), submission.csrfToken())) {
                return unavailable();
            }
            if (isBlank(submission.username()) || isBlank(submission.password())) {
                return Uni.createFrom().item((SubmitResult) new SubmitResult.Denied(form(entry)));
            }
            return login.login(realm, submission.username(), submission.password())
                    .flatMap(result -> switch (result) {
                        case LoginResult.Denied denied ->
                                Uni.createFrom().item((SubmitResult) new SubmitResult.Denied(form(entry)));
                        case LoginResult.Authenticated authenticated -> answer(realm, entry, authenticated);
                    });
        });
    }

    private Uni<SubmitResult> answer(
            RealmKey realm, PendingAuthorization entry, LoginResult.Authenticated authenticated) {
        return pending.consume(realm, entry.transactionId()).flatMap(consumed -> {
            if (consumed == null) {
                // Another post of the same form won the consume.
                return unavailable();
            }
            AuthorizationRequest request = consumed.request();
            return authorize.authorize(request, authenticated.subjectId())
                    .map(result -> switch (result) {
                        case AuthorizeResult.Issued issued -> (SubmitResult) new SubmitResult.Completed(
                                request.redirectUri(), issued.code(), issued.state(),
                                authenticated.sessionId());
                        case AuthorizeResult.Failed failed ->
                                new SubmitResult.Refused(failed.error(), failed.description());
                    });
        });
    }

    private static Form form(PendingAuthorization entry) {
        return new Form(entry.transactionId(), entry.csrfToken(), entry.request().redirectUri());
    }

    private static boolean bound(PendingAuthorization entry, String binding) {
        return sameSecret(entry.bindingHash(), hash(binding));
    }

    /** Constant-time comparison, so a guess learns nothing from how long the check took. */
    private static boolean sameSecret(String expected, String presented) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII), presented.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hash(String secret) {
        try {
            return B64URL.encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static Uni<SubmitResult> unavailable() {
        return Uni.createFrom().item(new SubmitResult.Unavailable());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
