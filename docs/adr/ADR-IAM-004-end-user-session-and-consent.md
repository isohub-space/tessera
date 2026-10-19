# ADR-IAM-004 — End-user session and consent: cookie-backed sessions behind the `X-Subject-Id` seam, password-only login, per-client consent

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-10-03 |
| Ratified | 2026-10-19 |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (standalone public origin), [ADR-IAM-005](ADR-IAM-005-oidf-basic-op-conformance-in-ci.md) (conformance) |

---

## Background

`/authorize` takes the logged-in user from an `X-Subject-Id` header, but nothing set it. Login, a session cookie and consent were added to fill that gap ([#76](https://github.com/isohub-space/tessera/pull/76)). This record states those choices. D1's enforcement rule and D5's login page are decided but not yet built.

## D1 — Consent per user and client, enforced for every client

**Decision.** Consent is stored per `(user, client)` as a set of scopes. `/authorize` requires consent covering the requested scopes for every client, with no first-party exemption. Enforcement is not yet built.

**What it means.** Recording consent again replaces the set. The `consent` table is unique on `(tenant_id, baseline_id, user_id, client_id)` and stores the scopes as `granted_scopes`.

**Consequences.**
1. A consent change replaces the whole set, with no history of earlier grants.
2. Per-scope consent would need a new schema grain, a consent request with a decision per scope, and a rule for partial grants at `/authorize`.

**Why.** No current flow lets a user grant some requested scopes and refuse others, so a finer grain would store a distinction nothing can produce. An exemption for first-party clients would make the decision depend on how a client is classified.

## D2 — The session cookie

**Decision.** The session cookie is `HttpOnly; Secure; SameSite=Strict`, with a fixed name (`tessera_session`) and fixed flags. Sessions expire after a configured absolute lifetime (`iam.login.session-ttl`, default 8 hours), never extended on use.

**What it means.** The value is a server-minted UUIDv7 session id with 74 random bits and no claims; login never adopts an id the caller presents. Logout marks the session revoked, clears the cookie, and is idempotent.

**Consequences.**
1. An active user is logged out at the end of the lifetime, and an idle session lives that long.
2. `SameSite=Strict` works only when the login form is same-site with tessera.

**Why.** The flags are security properties no supported deployment needs weaker, so making them configurable would only add a way to weaken them. The lifetime is policy.

## D3 — A filter turns the cookie into `X-Subject-Id`

**Decision.** `SessionCookieFilter` turns the session cookie into `X-Subject-Id` and, by default, strips any header a caller sent. `/authorize` is unchanged.

**What it means.** The filter runs after `TenantResolutionFilter` on every tenant-scoped request. If the cookie does not resolve, the header stays absent and the resource refuses with `access_denied`: `400` at `/authorize`, `401` at `/consent`. The filter never answers with an error itself, so it cannot be used to probe for sessions. `iam.subject.trust-header=true` turns off the stripping, for a deployment whose own ingress sets the header.

**Consequences.**
1. One session lookup per request with a cookie.
2. One place decides which subject a request carries, for every tenant-scoped resource, including future ones.

## D4 — Password-only login

**Decision.** Login is password-only, with Argon2id. An unknown user and a wrong password get identical responses. Failures are throttled per `(tenant, username)` with a refilling budget, not a hard lockout.

**What it means.** `POST /login` takes a form and returns `204` with the cookie, or `401 invalid_credentials`. The verifier runs one Argon2 pass on every reject path. A spent budget looks like a wrong password: no `429`. `/login` is also rate limited by source IP.

**Consequences.**
1. The throttle budget is per instance, so N instances allow N times the guesses, and a restart resets it.
2. Someone who knows a username can keep its owner locked out, bounded by the refill rate.
3. Response timing matches only while stored hashes use the same cost as the equaliser hash, and no test covers it.

## D5 — A hosted login page: not yet

**Decision.** MFA is out of scope. A replaceable, server-rendered login and consent page that `/authorize` redirects to is planned for Wave 2. Until then, the relying party serves its own form and posts to `/login`, allowed through the deny-by-default CORS policy.

**Consequences.**
1. Until the page exists, `/authorize` without a session refuses with `400` and does not redirect. Conformance testing waits for it (ADR-IAM-005).

## Rejected alternatives

- **Per-scope consent now.** Needs a new schema grain, and no current flow lets a user split a request.
- **A consent exemption for first-party clients.** Makes the consent decision depend on how a client is classified.
- **Configurable cookie flags.** The only reason to configure them is to weaken them.
- **Reading the session inside each resource.** Every subject-bearing resource would have to remember to do it.
- **Trusting a caller-supplied `X-Subject-Id` by default.** On a public origin it lets any caller name any subject.
- **A hard account lockout.** Lets anyone who knows a username lock its owner out for the whole window.

## Known defects

- A second consent for the same user and client fails instead of replacing.
- Login is not scoped to the baseline: a user can sign in to another baseline of the same tenant, and the consent path's user lookup has the same gap.
- Expired sessions are never purged.
- A new login or a password change does not end earlier sessions.
- No test covers the same-site and cross-site topologies.
