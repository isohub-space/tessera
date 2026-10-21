package dev.tessera.iam.adapter.rest.support;

import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import java.util.concurrent.atomic.AtomicInteger;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Test double for {@link ClientSecretVerifierPort} (the Argon2id-backed verifier is owned by
 * the persistence layer). Accepts a single fixed secret for the known confidential client and
 * rejects everything else, so the flow tests can drive both the authenticated and the
 * authentication-failure ({@code invalid_client}) paths.
 */
@Mock
@ApplicationScoped
public class FakeClientSecretVerifier implements ClientSecretVerifierPort {

    public static final String CORRECT_SECRET = "s3cr3t-correct-horse-battery-staple";

    /** How many times the sentinel was verified: the no-client path must always reach a verifier. */
    public static final AtomicInteger NO_CLIENT_CALLS = new AtomicInteger();

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        if (ClientSecretVerifierPort.NO_CLIENT.equals(clientId)) {
            NO_CLIENT_CALLS.incrementAndGet();
        }
        boolean ok = (FakeClientRepository.CONFIDENTIAL_IDENTITY.equals(clientId)
                || FakeClientRepository.MACHINE_IDENTITY.equals(clientId))
                && CORRECT_SECRET.equals(presentedSecret);
        return Uni.createFrom().item(ok);
    }
}
