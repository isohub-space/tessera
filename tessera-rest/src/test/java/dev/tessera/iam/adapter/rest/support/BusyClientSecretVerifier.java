package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.profile.IfBuildProfile;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;

/** A verifier that is always saturated, active only under the {@code busy-verifier} profile. */
@Alternative
@Priority(10)
@ApplicationScoped
@IfBuildProfile("busy-verifier")
public class BusyClientSecretVerifier implements ClientSecretVerifierPort {

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        return Uni.createFrom().failure(new CredentialVerificationBusyException(1));
    }
}
