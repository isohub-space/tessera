package dev.tessera.observability.audit;

import java.util.Optional;

/**
 * Resolves the {@code keyId} recorded on a checkpoint to the key that actually signed it.
 *
 * <p>This port exists because a checkpoint's {@code keyId} is a <em>selector</em>, not a
 * cryptographic binding: verification has to look the named key up rather than assume the
 * key that happens to be signing right now is the one that signed back then. Verifying
 * against the ambient signer — which is what the audit log used to do — quietly conflates
 * three different situations: a genuine checkpoint, a tampered one, and one whose key is
 * simply not present any more.
 *
 * <p>An implementation answers {@link Optional#empty()} for a {@code keyId} it does not
 * know. That is deliberately not the same answer as "invalid": the caller turns it into
 * {@link CheckpointVerification.UnknownKey}, which says the checkpoint could not be judged
 * rather than that it failed. Reporting an unresolvable key as a verification failure is
 * how tamper-evidence stops meaning anything — an operator cannot tell a rewritten log
 * from a rotated key.
 *
 * <p>The bundled implementation knows only the key this process is signing with, which is
 * as much as an in-process ephemeral key can support. A deployment with durable key
 * custody (a KMS, an HSM, a key table) supplies its own bean and thereby makes checkpoints
 * from previous boots verifiable, without any change to the audit core.
 */
public interface CheckpointKeyResolver {

    /**
     * @param keyId the identifier recorded on the checkpoint; never {@code null} or blank
     * @return a verifier for that key, or {@link Optional#empty()} if this resolver holds
     *         no key by that name
     */
    Optional<CheckpointVerifier> resolve(String keyId);
}
