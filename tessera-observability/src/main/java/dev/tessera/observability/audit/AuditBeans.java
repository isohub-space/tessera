package dev.tessera.observability.audit;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * CDI producers for the audit subsystem's collaborators.
 *
 * <p>Supplies the default {@link CheckpointSigner} — an in-process
 * {@link Ed25519CheckpointSigner} whose {@code keyId} is configurable via
 * {@code iam.audit.checkpoint.key-id}. A deployment that manages the signing key
 * externally provides its own {@link CheckpointSigner} bean, which (being more
 * specific than this {@code @DefaultBean}) replaces the bundled one without any
 * change to the audit core.</p>
 */
@ApplicationScoped
public class AuditBeans {

    /**
     * The bundled in-process Ed25519 checkpoint signer. Marked
     * {@link io.quarkus.arc.DefaultBean} so a deployment-supplied
     * {@link CheckpointSigner} takes precedence.
     *
     * @param keyId the configured signing-key identifier
     * @return the default signer
     */
    @Produces
    @ApplicationScoped
    @io.quarkus.arc.DefaultBean
    public CheckpointSigner checkpointSigner(
            @ConfigProperty(name = "iam.audit.checkpoint.key-id", defaultValue = "audit-checkpoint-ed25519")
            String keyId) {
        return Ed25519CheckpointSigner.generate(keyId);
    }
}
