// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Test double for {@link ClientKeySourcePort}: the {@code private_key_jwt} client of
 * {@link FakeClientRepository} has the public keys of {@link #CLIENT}; no other client has any.
 */
@Mock
@ApplicationScoped
public class FakeClientKeySource implements ClientKeySourcePort {

    /** The key pair the keyed client registered. */
    public static final AssertionTestClient CLIENT = new AssertionTestClient();

    @Override
    public Uni<AssertionTrust> trustFor(RealmKey realm, ClientId clientId) {
        String keyed = FakeClientRepository.KEYED_CLIENT_ID;
        return Uni.createFrom().item(FakeClientRepository.KEYED_IDENTITY.equals(clientId)
                ? new AssertionTrust(keyed, keyed, CLIENT.jwks())
                : null);
    }
}
