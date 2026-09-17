package dev.tessera.observability.audit;

import java.util.Objects;
import java.util.Optional;

/**
 * The bundled {@link CheckpointKeyResolver}: it knows exactly one key — the one this
 * process is signing with.
 *
 * <p>That is as much as an in-process, process-lifetime key can honestly support, and
 * saying so explicitly is the point. Every checkpoint written by an earlier boot names a
 * key this resolver does not hold, so it answers {@link Optional#empty()} and the audit
 * log reports {@link CheckpointVerification.UnknownKey} — "cannot judge" — instead of the
 * indistinguishable failure it used to report.
 *
 * <p>A deployment that keeps its checkpoint key in durable custody replaces this bean with
 * one that resolves retired keys too. Nothing else has to change: rotation and restart
 * become verifiable purely by making more keys resolvable.
 */
public final class ActiveSignerKeyResolver implements CheckpointKeyResolver {

    private final CheckpointSigner signer;

    public ActiveSignerKeyResolver(CheckpointSigner signer) {
        this.signer = Objects.requireNonNull(signer, "signer must not be null");
    }

    @Override
    public Optional<CheckpointVerifier> resolve(String keyId) {
        if (keyId == null || !keyId.equals(signer.keyId())) {
            return Optional.empty();
        }
        return Optional.of(signer);
    }
}
