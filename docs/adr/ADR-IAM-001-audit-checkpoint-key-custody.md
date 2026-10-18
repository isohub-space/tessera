# ADR-IAM-001 — Key custody for audit checkpoint signing

| Field | Value |
|---|---|
| Status | **Proposed** — awaiting ratification. Not a decision until accepted. |
| Date | 2026-09-11 |
| Renamed | 2026-10-18: filed as `ADR-001`, renamed `ADR-IAM-001` to join the series of the later records. Findings from a parallel draft of the same review are merged in [Additional findings](#additional-findings-merged-2026-10-18). |
| Spike | key custody for audit checkpoint signing (time-box 2 days, deliverable = this record) |
| Unblocks | the KMS-backed audit-checkpoint signing-key work, referred to below as *the implementation item* |
| Supersedes | nothing. This is the first ADR in this repository; see [Conventions established here](#conventions-established-here). |

---

## Context

The spike asked two entangled questions:

1. What external key custody backs Tessera's signing keys, and does it cover both
   consumers — the audit checkpoint signer and the token signing keys?
2. How does a checkpoint's `keyId` become a real cryptographic binding rather than an
   advisory label?

Investigating the code changed the shape of both questions. Three findings below
contradict the premises the spike was written on. They are stated first because they
shrink the decision considerably.

### Finding 1 — `keyId` is *already* inside the signing input

The spike asks whether making `keyId` a binding requires it to enter
`AuditCheckpoint.signingInput()`, and treats that as "a **format change** to
already-signed checkpoints".

It is already there. `AuditCheckpoint.java:55-65`:

```java
static String signingInput(
        String tenant, long headSequence, String headHash, Instant createdAt, String keyId) {
    StringBuilder sb = new StringBuilder(96);
    sb.append("checkpoint-v1\n");
    field(sb, "tenant", tenant);
    field(sb, "headSeq", Long.toString(headSequence));
    field(sb, "headHash", headHash);
    field(sb, "createdAt", createdAt.toString());
    field(sb, "keyId", keyId);          // <-- already covered
    return sb.toString();
}
```

Fields are length-prefixed (`key=<utf8len>:<value>\n`), so the encoding is
unambiguous and not vulnerable to field-splitting. The relabel attack the spike
describes — "a checkpoint signed under key A and relabelled as key B" — **already
fails**: changing `keyId` changes the signed bytes, so A's signature no longer
verifies, and B never signed those bytes.

**Consequence: no signing-input format change is required, and there is no migration
problem for already-signed checkpoints.** That was the single highest-intension part of
the spike and it is already resolved in code. The `checkpoint-v1` prefix stays as-is.

The javadoc on `CheckpointSigner.keyId()` (`CheckpointSigner.java:15-20`) still says
this label is "the selector, not itself a cryptographic binding". **That javadoc is
stale and should be corrected** — it describes a weaker property than the code provides.

### Finding 2 — the binding is nonetheless vacuous, for two different reasons

`keyId` being in the signed bytes only binds a signature to a *label*. Two defects make
that label meaningless in practice:

**(a) The label is not unique per key.** `AuditBeans.java:28-35`:

```java
@Produces
@ApplicationScoped
@io.quarkus.arc.DefaultBean
public CheckpointSigner checkpointSigner(
        @ConfigProperty(name = "iam.audit.checkpoint.key-id", defaultValue = "audit-checkpoint-ed25519")
        String keyId) {
    return Ed25519CheckpointSigner.generate(keyId);
}
```

`Ed25519CheckpointSigner.generate` mints a **fresh key pair**
(`Ed25519CheckpointSigner.java:48-58`), while the `keyId` comes from static
configuration and defaults to a constant. So every process start produces a new private
key wearing the *same* name. One label, unboundedly many keys, and nothing in the
checkpoint records which generation signed it.

**(b) Nothing ever resolves `keyId` to a key.** `TenantAuditLog.verifyCheckpoint`
(`TenantAuditLog.java:165-172`) verifies against the ambient injected signer and never
reads `checkpoint.keyId()`:

```java
if (!tenant.equals(checkpoint.tenant())
        || !signer.verify(checkpoint.signingInput(), checkpoint.signature())) {
    return Uni.createFrom().item(false);
}
```

There is no `keyId → public key` resolution anywhere in the repository, and no
publication of the checkpoint public key in any form.

**Consequence: every restart silently invalidates every prior checkpoint.** They do not
become "unselectable"; they become permanently unverifiable, because the only key that
could verify them no longer exists anywhere. A tamper-evidence mechanism that resets its
own root of trust on every deployment is not currently providing tamper evidence.

The mechanism is already proven by a test in the repository —
`Ed25519CheckpointSignerTest.wrongKeyRejected` (`:40-49`) asserts that a signature from
one generated key does not verify under another. That test reads as a correctness
property; combined with `AuditBeans` minting a new key per boot, it is also a
description of what happens to yesterday's checkpoints after a deploy.

This — not the signing-input format — is the actual defect. It is also a live
correctness bug, not merely a missing production feature.

### Finding 3 — the estate is *not* EdDSA-only

The spike states the token path enforces an "`EdDSA`-only, `HS*`-forbidden policy" and
asks whether a provider lacking Ed25519 would force a divergence.

It would not. `SigningAlgorithm.java:19-25` already admits two:

```java
EdDSA("OKP", "Ed25519"),
ES256("EC", "P-256");
```

with `EdDSA` merely the *default* (`defaultAlgorithm()`), and `ES256` present
deliberately "for interoperability with verifiers that do not yet support EdDSA".
`DiscoveryEndpointTest.noSymmetricSigningAlg` asserts
`contains("EdDSA", "ES256")` and forbids only `HS*` — the policy is
**asymmetric-only**, not EdDSA-only.

**Consequence: a custody provider that offers ECDSA P-256 but not Ed25519 is already
compliant with published estate policy.** This removes what would otherwise have been
the main constraint on provider choice, and it is why the recommendation below can be
made without first fixing the cloud.

### What the KMS references actually are

Confirmed: every `kms|hsm` occurrence in tracked files is prose, javadoc, or a seam
marker. There is no provider SDK, no integration, no configuration. Full list
(`README.md:28,57,140,289`; `KeyProviderPort.java:21`; `CheckpointSigner.java:9,17`;
`EnvelopeCipher.java:20,22,83`; `SigningKeyEntity.java:61`;
`DbKeyProviderAdapter.java:30,31,37,38,39`; `SigningKeyBeans.java:20,57`;
`SigningKeyConfig.java:11,30`). The one hit in
`TestClientCertificate.java:26` is base64 inside a test certificate, not a reference.

The spike's characterisation is correct: these are seams, not decisions.

### The two consumers are not alike

| | Audit checkpoint signer | Token signing keys |
|---|---|---|
| Port | `CheckpointSigner` | `KeyProviderPort` |
| Call rate | 1 sign per tenant per interval (`iam.audit.checkpoint.interval`, default `1h`, `CheckpointScheduler.java:37-39`) | 1+ sign per token issuance |
| On request path | No — scheduled, off the event loop | Yes |
| Latency sensitivity | None | Direct user-facing |
| Key lifecycle model | **None** | `PENDING → ACTIVE → RETIRING → RETIRED` (`SigningKeyState`, `package-info.java:6`) |
| Public key publication | **None** | JWKS, publish-before-sign (`KeyProviderPort.publishedJwks`) |
| Private key exposure | In-process, in heap | Never leaves provider (`sign`-as-operation) |

The checkpoint signer is the weaker of the two on every row. The token path already has
the model the checkpoint path is missing.

---

## Decision

### D1 — Custody boundary: back checkpoint signing with `KeyProviderPort`, not a second mechanism

The checkpoint signer adopts the **existing `KeyProviderPort` sign-as-operation
contract** rather than introducing a parallel custody path. `CheckpointSigner` stays as
the audit module's port; a new adapter implements it by delegating to
`KeyProviderPort.sign(...)`.

Rationale:

- It answers "where is the public key published?" with a mechanism that already exists
  and is already reachable by external verifiers — the realm JWKS — instead of
  inventing a second publication channel for one key.
- It inherits `PENDING → ACTIVE → RETIRING → RETIRED` and publish-before-sign, which is
  exactly the rotation story the spike asks for and which the checkpoint path has no
  version of.
- It collapses the estate to **one** custody decision. Choosing separately for each
  consumer is the "splits the estate" outcome the spike warns against, and there is no
  requirement that pulls the two apart.
- The private key stops living in the audit process's heap.

### D2 — Provider: an external KMS behind `KeyProviderPort`, selected by this rule

The spike requires naming one rather than restating "a KMS". Naming one also depends on
a hosting decision that is explicitly out of scope. The decision rule resolves that:

- **If the estate's cloud is already fixed** (or will be before implementation starts): use that
  cloud's managed KMS with **ES256 / ECDSA P-256** for the checkpoint key. Permitted by
  D-Finding-3, no new vendor, no new trust root.
- **If Ed25519 uniformity across both consumers is required**, or the estate must stay
  cloud-portable: use **HashiCorp Vault Transit**, which does offer Ed25519
  sign-as-operation.

**Recommended default: the managed KMS of the estate's cloud, on ES256.** It is the
lowest new-moving-parts option, the checkpoint key is the ideal first candidate (see
D3), and ES256 is already a published, supported algorithm.

> **Verify before implementing.** Asymmetric-signing algorithm support differs per
> provider and changes over time; my information has a cutoff and the major clouds have
> historically offered RSA and ECDSA but **not** Ed25519 for KMS signing. The implementation item must
> re-confirm the chosen provider's current algorithm list, quotas and regional
> availability against vendor documentation before committing. Do not treat the
> Ed25519-availability claims in this ADR as current fact.

### D3 — Invocation: remote sign per checkpoint, not a re-attested local key

Sign remotely, per checkpoint. The load is `tenants × (1 / interval)` — at the default
`1h`, a 1,000-tenant deployment is ~1,000 signs/hour. This is off the request path,
concurrency-capped (`ConcurrentExecution.SKIP`), already failure-isolated per tenant,
and already tolerant of a slow run. A locally-held, periodically re-attested key would
reintroduce the in-heap private key this ADR exists to remove, in exchange for savings
on a workload this small.

The implementation item should carry an explicit budget line for sign-request cost and provider
throttling limits at the target tenant count, and confirm the per-tenant error recovery
in `CheckpointScheduler.checkpointAllTenants` degrades correctly when the provider
throttles rather than failing an entire sweep.

### D4 — `keyId` binding: keep the signing input; make the label identify the key

**No change to `AuditCheckpoint.signingInput()` and no migration of existing
checkpoints.** The binding gap is closed on the two real defects instead:

1. **`keyId` must be derived from the key, not configured.** Use the key's JWK
   thumbprint (RFC 7638) or the provider's own immutable key version identifier —
   something that changes when the key changes. Retire
   `iam.audit.checkpoint.key-id` as a key *name*; a static operator-chosen label is what
   makes the current binding vacuous.
2. **Verification must resolve `keyId`.** `verifyCheckpoint` must look the checkpoint's
   `keyId` up against published key material and verify under *that* key, rather than
   against whichever signer happens to be injected. Verifying a historical checkpoint
   against the current signer is only correct when there has never been a rotation —
   which is precisely the case that cannot be assumed.

Together these make `keyId` a binding in substance: the label is in the signed bytes
(already true), the label names exactly one key (1), and the verifier is obliged to use
the key the label names (2).

### D5 — Verifier key resolution

`StreamingAuditVerifier` and any offline verifier resolve `keyId` through the realm
JWKS published by `KeyProviderPort.publishedJwks`. A `RETIRING` key stays published, so
a checkpoint signed shortly before a rotation still verifies — the same property the
token path relies on. `RETIRED` keys are withdrawn, which is a real constraint on audit:

> **Open question for ratification (OQ-1):** audit checkpoints are long-lived evidence,
> but the JWKS withdraws `RETIRED` keys. A checkpoint older than the retirement horizon
> becomes unverifiable through JWKS alone. This needs either an archival public-key
> record with a retention period matching the audit retention period, or an explicit,
> written acceptance that checkpoints expire. **This is a compliance-facing choice, not
> an engineering one, and is deliberately left open.**

### D6 — The bundled signer stays, scoped to dev/test

`Ed25519CheckpointSigner` remains the `@DefaultBean` so the service stays self-contained
for development and tests. But it must stop being silently acceptable in production:
`SigningKeyBeans.requireProductionMasterKey` (`SigningKeyBeans.java:47-59`) already
establishes exactly the right precedent — refuse to boot a `LaunchMode.NORMAL` run on a
development-grade key, with an actionable message. The implementation item should apply the same
fail-closed treatment to a production run that has no external checkpoint signer
configured.

Its per-boot key regeneration should also be made honest in the meantime by deriving the
`keyId` from the generated key (D4.1), so dev behaviour stops modelling a property that
production must not have.

---

## Alternatives considered

**A1 — Stay in-process; close the implementation item as NO GO.** Rejected. The audit chain's purpose is
tamper-evidence against a party who can write the audit store. An in-process key held by
the very process that writes the chain gives that party both the ability to rewrite
history and the key to re-sign it, so the signature attests nothing against the threat
it exists for. The spike allows this outcome; the threat model does not.

**A2 — A separate custody mechanism for checkpoints only.** Rejected. Two providers, two
trust roots, two rotation stories and two publication channels, for one low-volume key —
and it is the "splits the estate" failure the spike names. D1 gets the same isolation
with the existing port.

**A3 — Keep a local key, periodically re-attested by the KMS.** Rejected for now; see
D3. It trades the property being bought (no private key in the audit process) for a cost
saving on a negligible workload. Revisit only if a measured cost or throttling problem
appears at real tenant counts.

**A4 — Version the signing input to `checkpoint-v2` to add a stronger binding.**
Rejected as unnecessary. Finding 1 shows `keyId` is already covered; a v2 would impose a
dual-verification migration for no gain. Retained as an option only if OQ-1 concludes
that additional material (e.g. an algorithm identifier) must be bound — note that the
current input does **not** bind the algorithm, which is acceptable while `keyId`
resolves to exactly one key of one algorithm, and would need revisiting if that ceased
to hold.

---

## Consequences

**Positive.** One custody decision covers both consumers. Rotation, publication and
verifier resolution come from an existing, tested model. No format change, no migration
of signed checkpoints. The restart-invalidates-everything defect is fixed as a
by-product. The checkpoint private key leaves the application heap.

**Negative / accepted.** The checkpoint path gains a runtime dependency on the key
provider; a provider outage stops checkpoint production (tolerable — the scheduler
already recovers per tenant and the chain itself is unaffected). A per-sign cost appears
where there was none. If the chosen KMS lacks Ed25519, the estate runs EdDSA and ES256
side by side — permitted, but two algorithms to reason about.

**Follow-on work this creates** (each needs its own item; none is in the implementation item's
current scope):

- Correct the stale `CheckpointSigner.keyId()` javadoc (Finding 1).
- Fix `verifyCheckpoint` to resolve `keyId` (D4.2) — **this is a bug fix and should not
  wait for custody**; it is independently testable today against two generated signers.
- Archival public-key retention, pending OQ-1 (D5).
- Fail-closed production boot without an external checkpoint signer (D6).
- Token-key custody migration of `DbKeyProviderAdapter` onto the provider — out of scope
  here, confirmed only as far as one provider serving both.

---

## Additional findings (merged 2026-10-18)

A parallel draft of this record, written from the same review, carried the findings below,
which the text above lacks. They are merged here so the decision is recorded in one place.
They do not change D1–D6. Line references are as read on 2026-09-11 at `3397096`. Where a
finding was re-checked against `main` on the move, the note says so.

### Finding 4 — One process-wide key signs every tenant's checkpoints

`TenantAuditLog` injects a single `CheckpointSigner` (`TenantAuditLog.java:53`), and
`CheckpointScheduler` loops every tenant through it (`CheckpointScheduler.java:45-52`). The
audit subsystem has no `RealmKey`: it keys chains by a bare `String tenant`
(`TenantAuditLog.java:92,120`). D1 moves checkpoint signing onto the realm-scoped
`KeyProviderPort`, so the implementation item has to settle which realm's key signs a
tenant's checkpoint.

### Finding 5 — There are no already-signed checkpoints to migrate

Finding 1 shows no format change is needed. Separately, nothing durable exists to migrate:

- Nothing calls `TenantAuditLog.record(...)` outside the audit package and its own tests, so
  `auditLog.tenants()` is always empty and `CheckpointScheduler.checkpointAllTenants()`
  returns early every time it fires (`CheckpointScheduler.java:43`).
- `TenantAuditLogRepository` (`:23-79`) has no checkpoint method. A signed checkpoint is
  fired as a CDI event (`TenantAuditLog.java:131`), counted, and discarded.
- Nothing observes `AuditEvent`, so the durable sink described at `AuditEvent.java:5-11` has
  no implementation, and no migration creates an audit table.
- The domain emits `SideEffectRequest.RecordAuditEvent` (from `AuthFlowReducer`) and nothing
  interprets it. It carries a `RealmKey` while `TenantAuditLog.record` takes a
  `String tenant`, so the two halves are not type-compatible as written.

The implementation item is therefore free to change the tenant type from `String` to
`RealmKey` without a data migration.

### Finding 6 — D1 moves a module boundary

`tessera-observability` depends on no other `tessera-*` module and is built before
`tessera-domain`, `tessera-api` and `tessera-persistence` in the reactor, so
`CheckpointSigner` cannot reach `KeyProviderPort` or `RealmKey` today. The implementation
item picks one of:

- **(a)** supply the `KeyProviderPort`-backed `CheckpointSigner` from `tessera-server`, the
  composition root, through the `@DefaultBean` override seam at `AuditBeans.java:30`. This
  changes no module dependency and is the recommended option; or
- **(b)** move the audit core into `tessera-api`/`tessera-domain` and leave observability
  only the metrics wiring.

This is an implementation choice, not a custody decision, and is left open.

### Finding 7 — Telling the checkpoint key apart from token keys in the JWKS

D5 resolves `keyId` through the realm JWKS. The checkpoint key must still be
distinguishable from the token-signing keys published there. The `signing_key` table already
carries a `key_use` column defaulting to `'sig'` (`V2__signing_key_material.sql:19-25`), and
the selection index is `(tenant_id, issuer, key_use, state)`. Whether the checkpoint key is
published in the same JWKS under a distinct `key_use` or at a separate endpoint is left open
for the implementation item: the JWK `use` parameter has only the registered values `sig`
and `enc` (RFC 7517 §4.2), so overloading it needs care.

### Finding 8 — Provider algorithm support, with a dated source

D2 warns that the major clouds have historically not offered Ed25519 for KMS signing. For
Google Cloud, the platform `docker/cloudbuild.yaml` builds and pushes images for, that does
not hold. The provider's algorithm reference, read at `docs.cloud.google.com/kms/docs/algorithms`
on 2026-09-15 through a summarising fetch and not archived as served, lists:

| Need | Identifier | Description as published |
|---|---|---|
| Ed25519 signing | `EC_SIGN_ED25519` | *EdDSA on the Curve25519 in PureEdDSA mode* |
| ES256 fallback | `EC_SIGN_P256_SHA256` | *ECDSA on the P-256 Curve with a SHA-256 digest* |
| DEK wrapping | `GOOGLE_SYMMETRIC_ENCRYPTION` | *AES-256 in Galois Counter Mode*, `ENCRYPT_DECRYPT` purpose |

So on that provider the checkpoint key can stay on EdDSA, the published asymmetric-only
policy does not move, and the same provider can wrap `EnvelopeCipher`'s data keys, so the
estate does not split between a signing custodian and a separate key-wrapping custodian.

Not established: whether `EC_SIGN_ED25519` is generally available or in preview. That
matters for a compliance-adjacent signing path and must be confirmed against the page's own
status markers, as D2's verification note already requires.

Two criteria for the provider choice stay open: the credential model on an ephemeral CI
runner versus production, and whether custody is a compliance requirement or a hardening
goal, which sets whether it blocks a release.

### Finding 9 — Rotation is not enforced for token keys either

D1 inherits this. The rotation mechanics exist and are proven by integration tests
(`KeyRotationService.mintPending`/`promoteToActive`, `SigningKeyPipelineIT`), but nothing in
production drives retirement. `SigningKeyConfig.maxSigningTtl` (default `PT24H`) is read only
by a test stub, `KeyRotationPolicy.isDueForRetiring`/`isDueForRetired` are called only from
`KeyRotationPolicyTest`, and the `retiringGrace` parameter has no configuration property. The
retire-after-max-TTL invariant is modelled but not enforced. Re-checked on `main` on the move:
a first-boot provisioner now mints and promotes the initial key, but only when
`iam.bootstrap.enabled` is set, which requires fixed-tenant mode (`iam.tenancy.fixed-tenant`);
still nothing calls the retirement checks. This gap is separate from custody and needs its own item.

### Further alternatives considered

**Keep the in-process key and publish its public half at boot.** Rejected. A key that
changes on every restart cannot anchor a tamper-evidence claim across the restart, which is
the only interval that matters. Publishing it would make checkpoints look verifiable while
the verification window stayed one process lifetime.

**Derive the checkpoint key deterministically from `iam.keys.master-key`.** Rejected. It
makes a master-key compromise silently also a checkpoint-forgery capability with no separate
rotation, and it puts long-lived signing material in the same blast radius as the
data-key-wrapping key.

### Documentation defects found in passing

Neither is in this record's scope. Both were re-checked on `main` on the move and are still
present.

- `KeyProviderPort.java:65` links `{@link #sign(KeyId, byte[])}`, but the method takes three
  arguments (`:48`).
- `V900__dev_seed.sql` starts with `- dev-only seed.`, a single hyphen that is not a valid
  SQL comment token, and its seeded `ACTIVE` key has no private material and the literal
  public key `"x":"dev-placeholder-public-key"`. It satisfies the readiness count
  (`SigningKeyReadinessCheck`) while being unable to sign.

---

## Exit criteria status

| Spike exit criterion | Status |
|---|---|
| ADR committed, names a provider | This document; provider named by decision rule D2, with a recommended default. **Requires ratification.** |
| Ed25519 support stated | D2 — asymmetric-only policy confirmed (Finding 3); ES256 is an accepted fallback, so the question no longer blocks. Provider algorithm list must be re-verified at implementation. |
| Per-checkpoint vs re-attested | D3 — per checkpoint. |
| `keyId` binding, incl. `signingInput()` change | D4 — **no change, no migration**; the real defects are named instead (Finding 2). |
| Verifier resolution across rotation | D5, with OQ-1 open. |
| Bundled signer's fate | D6 — retained for dev/test, fail-closed in production. |
| Implementation item re-pointed | **Not done — see below.** |

The implementation item has **not** been re-pointed and no tracker status was changed, per the task's
"do not flip tracker status". Re-pointing should follow ratification, and the scope has
moved: the format-change risk is gone, and `verifyCheckpoint` resolution may be worth
splitting out as an independent fix that does not depend on the custody decision at all.

---

## Conventions established here

This repository had no ADR directory and no decision records before this file. It
therefore establishes, and should be confirmed or overridden on review:

- Location `docs/adr/`, filename `ADR-IAM-<number>-kebab-title.md`, zero-padded three-digit
  sequence from `001`. `IAM` is this project's own code, the one letter-coded ADR prefix the
  `pr-hygiene` workflow lets through. Every ADR of this project lives here and nowhere else.
- A `Status` taking `Proposed | Accepted | Superseded by ADR-IAM-<number>`, with
  **`Proposed` meaning not yet in force**.

This file was first filed as `ADR-001`, with plain-digit numbers. It was renamed on
2026-10-18 to match the `ADR-IAM-<number>` series the later records use.
