# ADR-IAM-001 — Key custody for audit checkpoint signing

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-09-11 |
| Ratified | 2026-10-19 |
| Relates to | [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (per-tenant key sets) |

---

## Background

Tessera keeps a hash-chained audit log per tenant. Every hour it signs a "checkpoint" over the head of each chain, so that a later rewrite of the log is caught.

Today the signing key is generated fresh in memory at every boot. That has two consequences. Every restart makes all earlier checkpoints unverifiable: the verifier reports them as signed by an unknown key. And whoever runs the process holds the key that could re-sign a forged history.

The audit log is not yet wired: nothing outside the audit package records events, and nothing stores checkpoints. So this record decides how the evidence will be guarded. The build follows once the audit log records events.

Two facts the decisions rest on:
- The token path already has what checkpoints lack: a key lifecycle (pending, active, retiring, retired), published public keys, private keys that never leave the provider, and a production start-up check (`SigningKeyBeans`).
- Signing policy is asymmetric-only, not EdDSA-only. `SigningAlgorithm` allows `EdDSA` (the default) and `ES256`.

## D1 — One custody path, a separate key

**Decision.** Checkpoint signing goes through the same provider interface as token signing (`KeyProviderPort`), not a second key system. The checkpoint key is its own KMS key, with its own access permission, in the same provider.

**What it means.** One provider, one rotation lifecycle and one way to publish public keys. The checkpoint key is kept apart from the token keys by being a separate key with its own permission.

**Consequences.**
1. The private key leaves the process memory.
2. The signer is supplied from the composition root (`tessera-server`), so no module dependency changes. `tessera-observability` builds before the modules that own `KeyProviderPort` and cannot reach it directly.
3. The build must settle which realm's key signs a tenant's checkpoints. The audit log keys chains by a bare `String tenant`, not a `RealmKey`. With nothing stored yet, changing that needs no data migration.
4. The build must settle how verifiers tell the checkpoint key apart from the token keys among the published keys. `signing_key` already has a `key_use` column, but the JWK `use` parameter has only `sig` and `enc` (RFC 7517 §4.2).
5. A provider outage pauses checkpoints. The chain itself is unaffected.
6. Token-key retirement is not enforced today: nothing outside tests calls `KeyRotationPolicy.isDueForRetiring` or `isDueForRetired`. The checkpoint key inherits that gap until it is closed.

## D2 — Provider

**Decision.** Use the deployment cloud's managed KMS. Sign with EdDSA where the provider offers it as generally available, and with ES256 otherwise. Both are already published signing algorithms.

**Consequences.**
1. No new vendor and no new trust root.
2. Confirm the provider's current algorithm list and general availability before building.
3. Enabling it needs the maintainers' cost approval.
4. Per-tenant key sets (ADR-IAM-003) multiply the number of keys.

## D3 — Remote sign per checkpoint

**Decision.** The KMS signs each checkpoint. No key is cached locally or re-attested.

**Consequences.**
1. One call per tenant per interval: about 720,000 a month at 1,000 tenants signed hourly. All of it is off the request path.
2. The build states the sign-request cost and the provider's throttling limits at the target tenant count.
3. When the provider throttles, the scheduler degrades per tenant rather than failing a whole sweep.

## D4 — `keyId` names exactly one key

**Decision.** The signed format does not change. `keyId` is derived from the key (a JWK thumbprint, RFC 7638, or the provider's key version), never configured. The verifier resolves the key the checkpoint names, not the one currently signing.

**What it means.** This is already how `main` works. `keyId` is inside the signed bytes, so relabelling a checkpoint breaks its signature. `TenantAuditLog.verifyCheckpoint` resolves the named key through `CheckpointKeyResolver`. Setting the old `iam.audit.checkpoint.key-id` property stops the server at startup.

## D5 — Old checkpoints stay verifiable

**Decision.** Retired keys leave the published key set, so retired public keys are archived for the audit retention period. A retiring key stays published.

**Consequences.**
1. A small archive of public keys, which are not secret.
2. Evidence stays verifiable for as long as it is kept.

## D6 — Production refuses to start without an external signer

**Decision.** The in-memory signer stays for development and tests. A production-mode start with no external checkpoint signer fails with an actionable message, as `SigningKeyBeans` already does for a development master key. There is no opt-out.

**Consequences.**
1. Once the audit log is wired, every production-mode deployment, demonstration ones included, needs a checkpoint KMS key or must run in a non-production mode.

**Why.** A production default that silently produces unverifiable checkpoints is the defect this record exists to close.

## Rejected alternatives

- **Stay in process.** The writer of the log would hold the key that re-signs it.
- **Publish the in-memory key at boot.** A key that changes on every restart cannot anchor evidence across the restart.
- **A second custody system for checkpoints only.** Two trust roots and two rotation stories for one key.
- **A local key re-attested by the KMS.** Puts the private key back in the process.
- **A `checkpoint-v2` signing format.** The key id is already signed.
- **Derive the key from the master key.** One compromise would forge both.
