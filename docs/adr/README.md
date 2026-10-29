# Architecture decision records

Every tessera decision record lives in this folder, and nowhere else.

| ADR | What it decides | Status |
|---|---|---|
| [001 Key custody for audit checkpoints](ADR-IAM-001-audit-checkpoint-key-custody.md) | Where the key that signs the audit log lives | Accepted |
| [002 Standalone public origin](ADR-IAM-002-standalone-public-origin.md) | Tessera is a public origin, not a service behind an app gateway | Accepted |
| [003 Tenant tier and per-tenant issuer](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) | Where a tenant's tier lives, how tenants stay isolated, what `iss` looks like (one issuer per `(tenant, baseline)` since the 2026-10-29 amendment) | Accepted, D3 amended 2026-10-29, one open item |
| [004 Session and consent](ADR-IAM-004-end-user-session-and-consent.md) | The login, session and consent design | Accepted |
| [005 OIDF conformance in CI](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) | Not until the hosted login page, session-aware `prompt`/`max_age`/`auth_time`, and `/userinfo` exist | Accepted |
| [006 Standalone provider for many sites and agents](ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) | Hosted sign-in for every relying party, brought forward; brokering in scope; sign-up as its own product; production bar before real accounts | Proposed |
| [007 Token exchange and the agent delegation profile](ADR-IAM-007-token-exchange-and-agent-delegation-profile.md) | The token exchange grant (RFC 8693) for delegation only: the actor is the key-authenticated client, every hop attenuates, every delegated token is bound and revocable through lineage, and no configuration state weakens security (three declared configuration points); the compile-time exclusion is lifted for this grant | Accepted |

## Convention

- File name: `ADR-IAM-<number>-kebab-title.md`, with a three-digit number. Numbers are assigned in filing order, with no gaps, and are never reused.
- `IAM` is this project's own code. It is the one letter-coded ADR prefix the `pr-hygiene` workflow allows.
- Header table: Status, Date, Ratified (once accepted), and Relates to.
- Status is one of `Proposed`, `Accepted`, or `Superseded by ADR-IAM-<number>`. `Proposed` means not yet in force.
- Body:
  - Background in plain words.
  - One section per decision, giving the decision, what it means, the consequences as a numbered list, and why (only when it is not obvious).
  - Rejected alternatives, one line each.
  - Open items, if any remain.
