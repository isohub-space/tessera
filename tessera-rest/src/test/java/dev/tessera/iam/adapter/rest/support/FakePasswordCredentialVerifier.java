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
    /** A UUID, as a real deployment's subject is, so the signed-in user can hold a refresh-token family. */
    public static final String SUBJECT = "5b0f3c2e-8a4d-4c1b-9e7f-2d6a1c3b4e5f";

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        boolean ok = USERNAME.equals(username) && CORRECT_PASSWORD.equals(password);
        return Uni.createFrom().item(ok ? Optional.of(SUBJECT) : Optional.empty());
    }
}
