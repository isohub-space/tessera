package dev.tessera.iam.adapter.rest.authcode;

import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Fail-closed fallback {@link ClientSecretVerifierPort}: verifies <em>no</em> secret.
 *
 * <p>The real verifier performs an Argon2id comparison against a stored credential and is
 * provided by the persistence layer. This fallback keeps the assembly bootable before that
 * adapter exists and is deliberately <strong>fail-closed</strong>: every presented secret is
 * rejected, so a confidential client can never authenticate against a server that has no
 * credential store wired (a public, PKCE-only client is unaffected — it presents no secret).
 *
 * <p>{@link DefaultBean} makes it active only when no other {@link ClientSecretVerifierPort}
 * bean exists; the persistence adapter takes precedence automatically once present.
 */
@DefaultBean
@ApplicationScoped
public class DenyingClientSecretVerifier implements ClientSecretVerifierPort {

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        // No credential store wired: authentication always fails (fail-closed).
        return Uni.createFrom().item(Boolean.FALSE);
    }
}
