package dev.tessera.observability.audit;

import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Periodically produces a signed checkpoint for every tenant that has an audit
 * chain, anchoring all entries written since the previous checkpoint.
 *
 * <p>The interval is configured by {@code iam.audit.checkpoint.interval} (a
 * Quarkus duration expression, default {@code 1h}); set it to {@code disabled} to
 * turn the periodic trigger off (for example in tests that drive checkpoints
 * explicitly). The signing and event publication are delegated to
 * {@link TenantAuditLog#checkpoint(String)}, so each run also emits the
 * {@code iam.audit.checkpoint} metric and fires {@link AuditEvent.CheckpointSigned}.</p>
 */
@ApplicationScoped
public class CheckpointScheduler {

    private static final Logger LOG = Logger.getLogger(CheckpointScheduler.class);

    private final TenantAuditLog auditLog;

    @Inject
    public CheckpointScheduler(TenantAuditLog auditLog) {
        this.auditLog = auditLog;
    }

    /**
     * Checkpoints every known tenant. Skipped concurrent overlap so a slow run never
     * stacks on the next tick. One tenant's checkpoint failing must not stop the others,
     * so each is recovered independently; the scheduled method blocks until the run
     * completes (the scheduler runs it off the event loop).
     */
    @Scheduled(
            every = "{iam.audit.checkpoint.interval:1h}",
            concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void checkpointAllTenants() {
        var tenants = auditLog.tenants().await().indefinitely();
        if (tenants.isEmpty()) {
            return;
        }
        for (String tenant : tenants) {
            try {
                auditLog.checkpoint(tenant).await().indefinitely();
            } catch (RuntimeException e) {
                // One tenant's checkpoint failing must not stop the others.
                LOG.errorf(e, "Failed to checkpoint audit chain for tenant %s", tenant);
            }
        }
        LOG.debugf("Signed audit checkpoints for %d tenant(s)", tenants.size());
    }
}
