# ADR-IAM-003 — Tenant tier source of truth, and a path-scoped issuer alongside header-only tenant resolution

| Field | Value |
|---|---|
| Status | **Proposed** — awaiting ratification. Not a decision until accepted. |
| Date | 2026-09-23 |
| Spike | tenant tier as source of truth + path-scoped issuer vs header-only tenant resolution (time-box 3 days, deliverable = this record) |
| Affects | tenant resolution, issuer configuration, signing-key topology, introspection, discovery/JWKS |
| Relates to | ADR-IAM-002 (standalone public origin), ADR-001 (key custody) |

---

## Context

<!-- findings -->

## Decisions

- **D1** — Tier source of truth.
- **D2** — The two-channel resolution rule.
- **D3** — Whether `iss` stays a single configured scalar.
- **D4** — Key topology and the shared-Starter-keyset question.
- **D5** — Per-realm discovery and JWKS, and the cache-TTL-vs-dwell invariant.
- **D6** — What is deliverable without a messaging layer.

## Alternatives considered

## Consequences

## Open decisions

## Exit criteria status
