// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Fail-closed fallback {@link ClientKeySourcePort}: no client has assertion keys, so no assertion
 * authenticates. The persistence adapter takes precedence wherever it is present.
 */
@DefaultBean
@ApplicationScoped
public class NoClientKeySource implements ClientKeySourcePort {

    @Override
    public Uni<AssertionTrust> trustFor(RealmKey realm, ClientId clientId) {
        return Uni.createFrom().nullItem();
    }
}
