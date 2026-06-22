/**
 * Tamper-evident, per-tenant audit log for the authorization server.
 *
 * <p>Each tenant's audited events form an independent hash chain
 * ({@link dev.tessera.observability.audit.AuditEntry}): every entry hashes over its
 * predecessor's hash, so altering, inserting, deleting or reordering any entry
 * breaks the chain, which {@link dev.tessera.observability.audit.AuditChain} detects.
 * {@link dev.tessera.observability.audit.TenantAuditLog} records entries, emits the
 * {@code iam.audit.*} metrics and fires
 * {@link dev.tessera.observability.audit.AuditEvent}s on an in-process channel that a
 * deployment observes to forward to a durable sink.
 * {@link dev.tessera.observability.audit.CheckpointScheduler} periodically signs each
 * chain's head into a {@link dev.tessera.observability.audit.AuditCheckpoint} via a
 * {@link dev.tessera.observability.audit.CheckpointSigner}, anchoring everything
 * written so far against later rewrites.
 */
package dev.tessera.observability.audit;
