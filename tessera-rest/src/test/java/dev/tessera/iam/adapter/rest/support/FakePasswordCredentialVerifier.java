package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;

/**
 * Test double for {@link PasswordCredentialVerifierPort} (the Argon2id-backed verifier is
 * owned by the persistence layer). Accepts one fixed username/password and resolves it to a
 * fixed subject; rejects everything else, so flow tests can drive both the authenticated and
 * the {@code invalid_credentials} paths.
 */
@Mock
@ApplicationScoped
public class FakePasswordCredentialVerifier implements PasswordCredentialVerifierPort {

    public static final String USERNAME = "alice";
    public static final String CORRECT_PASSWORD = "correct-horse-battery-staple";
    public static final String SUBJECT = "user-sub-alice";

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        boolean ok = USERNAME.equals(username) && CORRECT_PASSWORD.equals(password);
        return Uni.createFrom().item(ok ? Optional.of(SUBJECT) : Optional.empty());
    }
}
