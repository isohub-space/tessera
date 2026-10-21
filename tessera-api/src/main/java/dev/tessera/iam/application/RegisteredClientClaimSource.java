package dev.tessera.iam.application;

import dev.tessera.iam.application.port.out.ClaimSourcePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.domain.authflow.ClaimContext;
import dev.tessera.iam.domain.authflow.Subject;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.List;
import java.util.Set;

/**
 * The claim source for a client acting on its own behalf ({@code client_credentials}): the
 * subject is the wire {@code client_id}, and its roles are the ones registered for that client.
 * The client is resolved through the realm-scoped registry, so a client of another tenant has
 * no roles here. Roles are configuration, never code.
 */
public final class RegisteredClientClaimSource implements ClaimSourcePort {

    private final ClientRepositoryPort clients;

    public RegisteredClientClaimSource(ClientRepositoryPort clients) {
        if (clients == null) {
            throw new IllegalArgumentException("clients must not be null");
        }
        this.clients = clients;
    }

    @Override
    public Uni<ClaimContext> loadClaimContext(Subject subject, RealmKey realm, Set<String> scopes) {
        return clients.findByClientId(realm, subject.subjectId()).map(client -> {
            List<String> roles = client instanceof ConfidentialClient confidential
                    ? confidential.roles()
                    : List.of();
            return new ClaimContext(subject, realm, roles, scopes);
        });
    }
}
