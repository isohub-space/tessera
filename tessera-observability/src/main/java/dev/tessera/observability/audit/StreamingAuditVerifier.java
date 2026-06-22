package dev.tessera.observability.audit;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;

/**
 * Verifies an audit chain by folding the pure {@link AuditChain#verifyNext} step over a
 * reactive stream of entries, in O(1) memory.
 *
 * <p>This is the streaming analog of {@link AuditChain#verify(java.util.List)}: it never
 * collects the entries, it threads each one through the running
 * {@link AuditChain.State} and emits the final {@link AuditChain.Verification}. It is the
 * only place the {@code Multi} boundary meets the chain math — the math itself stays pure
 * and framework-free in {@link AuditChain}, and the stream comes from the outbound
 * {@link TenantAuditLogRepository} port. Once a link breaks the fold short-circuits (the
 * pure step turns subsequent entries into no-ops), so the result still pinpoints the
 * first failure.</p>
 */
public final class StreamingAuditVerifier {

    private StreamingAuditVerifier() {
    }

    /**
     * Folds {@code entries} (ascending sequence) through the pure chain step.
     *
     * @param entries the tenant's chain as a stream ordered by sequence; never null
     * @return a {@link Uni} emitting the verification outcome
     */
    public static Uni<AuditChain.Verification> verify(Multi<AuditEntry> entries) {
        return entries
                .onItem().scan(AuditChain::initialState, AuditChain::verifyNext)
                .collect().last()
                .onItem().ifNull().continueWith(AuditChain.State::initial)
                .map(AuditChain.State::result);
    }
}
