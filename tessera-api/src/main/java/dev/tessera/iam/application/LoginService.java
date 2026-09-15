package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.LoginUseCase;
import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Duration;

/**
 * Application service for the login endpoint: verifies a presented username/password and, on
 * success, establishes a session.
 *
 * <p>Framework-free (no CDI annotations), matching {@link AuthorizationService}'s shape: an
 * adapter constructs it from the outbound ports and a session TTL and exposes it as a bean.
 */
public final class LoginService implements LoginUseCase {

    private final PasswordCredentialVerifierPort credentials;
    private final SessionStorePort sessions;
    private final Duration sessionTtl;

    public LoginService(
            PasswordCredentialVerifierPort credentials, SessionStorePort sessions, Duration sessionTtl) {
        this.credentials = requireNonNull(credentials, "credentials");
        this.sessions = requireNonNull(sessions, "sessions");
        this.sessionTtl = requireNonNull(sessionTtl, "sessionTtl");
        if (sessionTtl.isZero() || sessionTtl.isNegative()) {
            throw new IllegalArgumentException("sessionTtl must be positive");
        }
    }

    @Override
    public Uni<LoginResult> login(RealmKey realm, String username, String password) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username must not be blank");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }

        return credentials.verify(realm, username, password)
                .flatMap(subject -> subject
                        .map(sub -> sessions.create(realm, sub, sessionTtl)
                                .map(session -> (LoginResult)
                                        new LoginResult.Authenticated(session.id(), sub)))
                        // Deliberately the same outcome for "no such user" and "wrong
                        // password" — collapsed by the verifier port already returning
                        // empty() for both; this is the last place that could leak the
                        // distinction and it does not.
                        .orElseGet(() -> Uni.createFrom()
                                .item(new LoginResult.Denied("invalid_credentials"))));
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
