# ADR-IAM-006 — A standalone identity provider for many sites and agents: hosted sign-in for every relying party, brokering in scope, sign-up as its own product

| Field | Value |
|---|---|
| Status | **Proposed** |
| Date | 2026-10-26 |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (standalone public origin), [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (issuer), [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (session, login page), [ADR-IAM-005](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) (conformance) |

---

## Background

Tessera was first deployed for one application, on the same site, whose front end served the login form and posted it to `/login` (ADR-IAM-004 D5). Its owner now runs it as a product of its own: one central provider, as a consumer account service is, that people and agents use to sign in to many relying parties on many registrable domains.

Facts the decisions rest on:
- The session cookie is `SameSite=Strict` (ADR-IAM-004 D2). Only a page on the same site as tessera can establish a session by posting to `/login`; a relying party on another site cannot.
- There is no hosted login page. `/authorize` without a session answers `400` and does not redirect (ADR-IAM-004 D5, ADR-IAM-005).
- Identity brokering is outside the current protocol scope.
- First boot provisions exactly one user. There is no provisioning API and no sign-up.
- A single-tenant deployment has one issuer, its configured base (ADR-IAM-003 D3).
- Agents already authenticate as clients: `client_credentials`, `private_key_jwt`, and keyless authentication through trusted external issuers.

## D1 — Tessera is a standalone identity provider for many relying parties

**Decision.** Tessera serves many relying parties, people and agents alike, from one deployment. A relying party is a client registration. A person has one account and uses it with every relying party; each relying party decides what that account may do there.

**Consequences.**
1. One deployment and one tenant can serve many sites. A tenant isolates customers of the provider, not the sites that use it.
2. No relying party's name, rule or data enters tessera's code; a relying party is configuration.
3. Agents are first-class clients, under the same issuer as people.

## D2 — The hosted sign-in page is every relying party's sign-in path, and it is brought forward

**Decision.** The server-rendered login page that ADR-IAM-004 D5 planned for Wave 2 is built next. `/authorize` without a session redirects to it, and every relying party, on any site, signs people in through it. A form served by a relying party and posted to `/login` remains possible only for a relying party on tessera's own site, and is not the recommended path.

**Consequences.**
1. The content security policy allows `form-action 'self'` on the login and consent pages only; everywhere else it stays `'none'` (pinned by `EdgeSecurityBaselineTest`).
2. The form carries CSRF protection, the page cannot be framed, and after login the browser returns only to the pending authorization request, never to a caller-supplied URL.
3. It closes the first of ADR-IAM-005's three gaps before conformance runs.
4. With a `Strict` session cookie, a person arriving from another site is not recognised on arrival and signs in once per relying-party site. Cross-site single sign-on would need a different cookie policy and its own record.

## D3 — Identity brokering is in scope

**Decision.** Tessera may act as a client of upstream OpenID providers and offer them on its hosted page ("continue with" an upstream account), so that relying parties keep one issuer.

**Consequences.**
1. Tessera's tokens carry tessera's `sub`; an upstream identity is never passed through as `sub`.
2. An upstream account is linked to an existing tessera account only with proof of control of both, never on equal email addresses alone. The stored link is the upstream `iss` and `sub`.
3. Upstream credentials live in the deployment's secret store, and an upstream `iss` is compared byte for byte.

## D4 — Self-service sign-up is a product of its own

**Decision.** Public sign-up is planned and released as its own product, not as a feature of the login page. Until it ships, accounts are invite-only: first boot provisions a declared list of users, idempotently and without overwriting existing rows, and a provisioning API follows.

**Consequences.**
1. A public release needs at least email delivery and verification, password reset and account recovery, abuse controls, and the legal texts and data-subject rights of the operator's jurisdiction. The sign-up plan states the minimum.
2. ADR-IAM-004 D5 keeps MFA out of scope; the sign-up plan revisits it.

## D5 — Real accounts need a production deployment first

**Decision.** A deployment that holds real people's accounts meets a production bar before the first one is created: a rehearsed backup and restore with stated recovery targets, a login path without a cold start, and an availability target. Running many instances follows its own design work.

## Rejected alternatives

- **One deployment per relying party.** It gives a person one account per site, which is the opposite of a central provider.
- **One tenant per relying party.** Multi-tenancy on a standalone origin is not solved (ADR-IAM-002), and tenants isolate customers, not sites.
- **Each relying party integrating upstream providers itself.** Every relying party would repeat account linking and hold upstream credentials.
- **Relying-party forms as the main path.** They fail for every relying party on another site (ADR-IAM-004 D2).
- **Public sign-up now.** There is no email delivery, recovery or abuse control yet.

## Open items

- Whether the session cookie should allow cross-site single sign-on (`Lax`), and what that costs.
- The upgrade path for a deployment whose issuer changes (ADR-IAM-003's open item) now has a first concrete use: moving an existing deployment to a new public name.
