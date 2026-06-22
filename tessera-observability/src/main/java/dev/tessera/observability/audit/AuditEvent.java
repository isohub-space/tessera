package dev.tessera.observability.audit;

/**
 * A CDI event fired whenever the audit log records an entry or produces a signed
 * checkpoint, forming the in-process {@code iam.audit.*} event channel.
 *
 * <p>Keeping publication as a CDI event decouples the audit core from any
 * particular sink: a deployment observes {@link AuditEvent} to forward entries and
 * checkpoints to a message broker, an append-only store, or a SIEM, without the
 * {@link TenantAuditLog} depending on that transport. The event {@link #kind()}
 * distinguishes the two {@code iam.audit.*} signals.</p>
 */
public sealed interface AuditEvent permits AuditEvent.EntryRecorded, AuditEvent.CheckpointSigned {

    /** The {@code iam.audit.*} signal this event represents. */
    enum Kind {
        /** A new chain entry was appended: {@code iam.audit.entry}. */
        ENTRY,
        /** A signed checkpoint was produced: {@code iam.audit.checkpoint}. */
        CHECKPOINT
    }

    /** @return the kind of audit signal. */
    Kind kind();

    /** @return the tenant the event pertains to. */
    String tenant();

    /**
     * A newly appended audit entry.
     *
     * @param entry the appended, self-hashed entry
     */
    record EntryRecorded(AuditEntry entry) implements AuditEvent {
        public EntryRecorded {
            if (entry == null) {
                throw new IllegalArgumentException("entry must not be null");
            }
        }

        @Override
        public Kind kind() {
            return Kind.ENTRY;
        }

        @Override
        public String tenant() {
            return entry.tenant();
        }
    }

    /**
     * A newly produced signed checkpoint.
     *
     * @param checkpoint the signed checkpoint
     */
    record CheckpointSigned(AuditCheckpoint checkpoint) implements AuditEvent {
        public CheckpointSigned {
            if (checkpoint == null) {
                throw new IllegalArgumentException("checkpoint must not be null");
            }
        }

        @Override
        public Kind kind() {
            return Kind.CHECKPOINT;
        }

        @Override
        public String tenant() {
            return checkpoint.tenant();
        }
    }
}
