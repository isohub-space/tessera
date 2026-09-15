package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.application.port.in.LoginUseCase.LoginResult;
import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("LoginService — verifies a credential and establishes a session on success")
class LoginServiceTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final AtomicInteger createCount = new AtomicInteger();

    private LoginService serviceAcceptingOnly(String username, String password, String subject) {
        PasswordCredentialVerifierPort credentials = (realm, u, p) -> Uni.createFrom().item(
                username.equals(u) && password.equals(p) ? Optional.of(subject) : Optional.empty());
        SessionStorePort sessions = new SessionStorePort() {
            @Override
            public Uni<Session> create(RealmKey realm, String subjectId, Duration ttl) {
                createCount.incrementAndGet();
                return Uni.createFrom().item(
                        new Session(realm, SessionId.generate(), subjectId, NOW, NOW.plus(ttl)));
            }

            @Override
            public Uni<Optional<Session>> find(RealmKey realm, SessionId id) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Uni<Void> invalidate(RealmKey realm, SessionId id) {
                throw new UnsupportedOperationException();
            }
        };
        return new LoginService(credentials, sessions, Duration.ofMinutes(30));
    }

    @Test
    @DisplayName("a correct credential establishes exactly one session and returns its subject")
    void correctCredentialAuthenticates() {
        LoginService service = serviceAcceptingOnly("alice", "correct-horse", "sub-alice");

        LoginResult result = service.login(REALM, "alice", "correct-horse").await().indefinitely();

        assertThat(result).isInstanceOfSatisfying(LoginResult.Authenticated.class,
                ok -> assertThat(ok.subjectId()).isEqualTo("sub-alice"));
        assertThat(createCount).hasValue(1);
    }

    @Test
    @DisplayName("a wrong password is Denied and establishes no session")
    void wrongPasswordDenied() {
        LoginService service = serviceAcceptingOnly("alice", "correct-horse", "sub-alice");

        LoginResult result = service.login(REALM, "alice", "wrong").await().indefinitely();

        assertThat(result).isInstanceOf(LoginResult.Denied.class);
        assertThat(createCount).hasValue(0);
    }

    @Test
    @DisplayName("an unknown username is Denied with the SAME reason as a wrong password (no oracle)")
    void unknownUsernameDeniedIdentically() {
        LoginService service = serviceAcceptingOnly("alice", "correct-horse", "sub-alice");

        LoginResult unknownUser = service.login(REALM, "bob", "anything").await().indefinitely();
        LoginResult wrongPassword = service.login(REALM, "alice", "wrong").await().indefinitely();

        assertThat(((LoginResult.Denied) unknownUser).reason())
                .isEqualTo(((LoginResult.Denied) wrongPassword).reason());
        assertThat(createCount).hasValue(0);
    }

    @Test
    @DisplayName("a blank username is rejected before the verifier is ever called")
    void blankUsernameRejected() {
        LoginService service = serviceAcceptingOnly("alice", "correct-horse", "sub-alice");

        assertThatThrownBy(() -> service.login(REALM, " ", "whatever"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
