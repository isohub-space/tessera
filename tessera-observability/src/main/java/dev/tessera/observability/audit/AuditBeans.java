package dev.tessera.observability.audit;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * CDI producers for the audit subsystem's collaborators.
 *
 * <p>Supplies the default {@link CheckpointSigner} — an in-process
 * {@link Ed25519CheckpointSigner} — and the matching {@link CheckpointKeyResolver}. Both
 * are {@link io.quarkus.arc.DefaultBean}s, so a deployment that manages the checkpoint key
 * externally replaces either or both without any change to the audit core. Replacing the
 * resolver is what makes checkpoints from earlier boots verifiable; replacing the signer
 * is what makes the key durable in the first place.
 */
@ApplicationScoped
public class AuditBeans {

    /**
     * The bundled in-process Ed25519 checkpoint signer, with a key id derived from the
     * key it generates.
     *
     * @param configuredKeyId the legacy {@code iam.audit.checkpoint.key-id} property, if a
     *                        deployment still sets it — accepted only to refuse it
     * @return the default signer
     * @throws IllegalStateException if {@code iam.audit.checkpoint.key-id} is set
     */
    @Produces
    @ApplicationScoped
    @io.quarkus.arc.DefaultBean
    public CheckpointSigner checkpointSigner(
            @ConfigProperty(name = "iam.audit.checkpoint.key-id") Optional<String> configuredKeyId) {
        // Refused rather than ignored. This signer mints a new key pair on every boot, so a
        // configured id would be a stable name over unstable material: every checkpoint
        // written under it would claim a key identity that the next boot silently hands to
        // different key material. Failing loudly here is the only answer that does not
        // leave an audit trail quietly unverifiable — and it names the two real options.
        if (configuredKeyId.isPresent()) {
            throw new IllegalStateException(
                    "iam.audit.checkpoint.key-id is set to '" + configuredKeyId.get()
                            + "', but the bundled checkpoint signer derives its key id from the"
                            + " key pair it generates at boot. A declared id would name"
                            + " different key material after every restart, which is what makes"
                            + " older checkpoints unverifiable. Remove the property, or supply"
                            + " your own CheckpointSigner and CheckpointKeyResolver beans backed"
                            + " by durable key custody.");
        }
        return Ed25519CheckpointSigner.generate();
    }

    /**
     * The bundled resolver, which knows only the key this process signs with.
     *
     * @param signer the active checkpoint signer
     * @return the default resolver
     */
    @Produces
    @ApplicationScoped
    @io.quarkus.arc.DefaultBean
    public CheckpointKeyResolver checkpointKeyResolver(CheckpointSigner signer) {
        return new ActiveSignerKeyResolver(signer);
    }
}
