package dev.tessera.iam.domain.authflow;

import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * A description of an effect the imperative shell must execute, emitted as data by
 * the {@link AuthFlowReducer}.
 *
 * <p>The functional core is the centre of a functional-core / imperative-shell
 * split: it <strong>never performs I/O</strong>. When a fold determines that
 * something must happen in the outside world — send an email, persist a session,
 * write an audit record, bump a brute-force counter — it returns a
 * {@code SideEffectRequest} describing the intent. The shell interprets the request
 * and performs the actual effect (reactively, transactionally, idempotently),
 * keeping {@code reduce} pure and deterministic.
 *
 * <p>Every member carries a {@link RealmKey} so the shell can route the effect to
 * the correct tenant scope (RLS write, per-tenant counter/cache) without
 * re-deriving tenancy.
 */
public sealed interface SideEffectRequest
        permits SideEffectRequest.SendVerificationEmail,
                SideEffectRequest.PersistSession,
                SideEffectRequest.RecordAuditEvent,
                SideEffectRequest.IncrementBruteForceCounter {

    /** The tenant/realm scope this effect must be executed within. */
    RealmKey realm();

    /**
     * Send a verification / notification email to a resolved subject.
     *
     * @param realm   the realm scope (never {@code null})
     * @param subject the recipient principal (never {@code null})
     */
    record SendVerificationEmail(RealmKey realm, Subject subject) implements SideEffectRequest {
        public SendVerificationEmail {
            requireRealm(realm);
            if (subject == null) {
                throw new IllegalArgumentException("SendVerificationEmail subject must not be null");
            }
        }
    }

    /**
     * Persist the authenticated session (with session-id regeneration in the shell).
     *
     * @param realm   the realm scope (never {@code null})
     * @param subject the authenticated principal (never {@code null})
     * @param atEpochMilli the shell-supplied creation instant, threaded in from the
     *                    driving event (never read from a clock here)
     */
    record PersistSession(RealmKey realm, Subject subject, long atEpochMilli) implements SideEffectRequest {
        public PersistSession {
            requireRealm(realm);
            if (subject == null) {
                throw new IllegalArgumentException("PersistSession subject must not be null");
            }
        }
    }

    /**
     * Write a tamper-evident audit record.
     *
     * @param realm        the realm scope (never {@code null})
     * @param eventType    a stable audit event type, e.g. {@code "AUTH_DENIED"}
     *                    (never {@code null} or blank)
     * @param detail       an audit-friendly detail string (never {@code null})
     * @param atEpochMilli the shell-supplied occurrence instant, threaded in from
     *                    the driving event
     */
    record RecordAuditEvent(RealmKey realm, String eventType, String detail, long atEpochMilli)
            implements SideEffectRequest {
        public RecordAuditEvent {
            requireRealm(realm);
            if (eventType == null || eventType.isBlank()) {
                throw new IllegalArgumentException("RecordAuditEvent eventType must not be null or blank");
            }
            if (detail == null) {
                throw new IllegalArgumentException("RecordAuditEvent detail must not be null");
            }
        }
    }

    /**
     * Bump the brute-force counter for a subject after a failed factor, so the shell
     * can apply lockout/backoff.
     *
     * @param realm   the realm scope (never {@code null})
     * @param subject the principal whose counter to increment (never {@code null})
     */
    record IncrementBruteForceCounter(RealmKey realm, Subject subject) implements SideEffectRequest {
        public IncrementBruteForceCounter {
            requireRealm(realm);
            if (subject == null) {
                throw new IllegalArgumentException("IncrementBruteForceCounter subject must not be null");
            }
        }
    }

    private static void requireRealm(RealmKey realm) {
        if (realm == null) {
            throw new IllegalArgumentException("SideEffectRequest realm must not be null");
        }
    }
}
