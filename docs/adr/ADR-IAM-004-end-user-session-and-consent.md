# ADR-IAM-004 — End-user session and consent: cookie-backed sessions behind the `X-Subject-Id` seam, password-only login, per-client consent

| Field | Value |
|---|---|
| Status | **Proposed** — awaiting ratification. Not a decision until accepted. |
| Date | 2026-10-03 |
| Records | decisions already implemented on `main` by #76; this record is written after the fact, from the code |
| Affects | `/login`, `/logout`, `/consent`, `/authorize`; session and consent persistence; credential throttling |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (standalone public origin) |

---

## Context

`AuthorizeResource` was written with a gap in it: it takes the authenticated end user's `sub` from the `X-Subject-Id` header and says that a login/consent front end, or an upstream authenticating proxy, is what puts it there. Nothing did. The `auth_session` and `consent` tables existed in V3, under RLS, with nothing writing them.

#76 filled that gap. It made several choices on the way that are easy to mistake for accidents: consent granularity, the cookie's flags, where the session meets `/authorize`, which credential to support first, and what not to build. This record states them, with the evidence in the code, so they can be ratified or reopened on purpose.

Every statement below is derived from the code on `main`. Where the code does not settle a point, the record says so under [Open points](#open-points-the-code-does-not-settle).

## Decisions

### D1 — Consent is recorded per (subject, client), not per scope

`ConsentUseCase` (`tessera-api/.../application/port/in/ConsentUseCase.java`) states the granularity: one consent per `(subject, client)` within a realm, holding the set of scopes the user agreed to release. `hasConsented` asks whether that set covers *at least* the requested scopes. `recordConsent` replaces the previous set for that pair, so narrowing and widening are both a re-record.

`PersistentConsentStore` (`tessera-persistence/.../consent/PersistentConsentStore.java`) stores the set as the space-separated `granted_scopes` column and checks coverage with `containsAll`. The `consent` table is unique on `(tenant_id, baseline_id, user_id, client_id)` (V3), which is exactly this grain.

**Why.** It matches the schema that already existed, so it shipped with no migration. It answers the question `/authorize` needs answered: does this user already allow this client these scopes? Nothing in the current flow lets a user grant some requested scopes and refuse others, so a finer grain would store a distinction nothing can produce.

**What per-scope consent would take.** A new grain in the schema: either a child table of `(consent_id, scope)` rows or a unique key that includes the scope, plus a migration that splits existing `granted_scopes` strings. A consent request and response that carry a per-scope decision, rather than the single `scope` form parameter `ConsentResource` reads today. And a rule for a partial grant at `/authorize`: whether the code is issued for the granted subset or the request is refused. `ConsentService` is a pass-through today and is where that rule would go.

### D2 — The session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, fixed name and flags; lifetime configured, expiry absolute

`SessionCookies` (`tessera-rest/.../session/SessionCookies.java`) builds the only `Set-Cookie` for a session:

- name `tessera_session`, `Path=/`;
- `HttpOnly`: the value is a session credential, never needed by script;
- `Secure`: never sent over plain HTTP;
- `SameSite=Strict`: never attached to a cross-site request;
- `Max-Age` equal to the session lifetime on login, and `Max-Age=0` with an empty value on logout.

The value is the session id: a UUIDv7 with 128 CSPRNG-drawn bits (`SessionId`). It carries no claims; everything else is server-side in `auth_session`. Login always mints a new id server-side and never adopts one presented by the caller.

**Lifetime and expiry.** The lifetime is `iam.login.session-ttl` (`LoginConfig`, default `PT8H`; `TESSERA_LOGIN_SESSION_TTL` in `tessera-server`'s `application.properties`). `PersistentSessionStore.create` sets `expires_at = now + ttl`. Expiry is absolute: nothing extends it on use, and there is no separate idle timeout. `PersistentSessionStore.find` treats a session as absent unless it is `AUTHENTICATED`, unexpired, and in the caller's baseline; RLS already limits it to the caller's tenant. Logout (`LogoutResource`) marks the row `REVOKED` and clears the cookie, and is idempotent.

**What is fixed, and why.** The flags and the name are constants, not configuration. The flags are security properties with no deployment that needs them weaker: every real deployment terminates TLS in front of tessera, and the login form is expected to be same-site with tessera (see the open point on `SameSite`). Making them configurable would only add a way to ship them off. The name is an implementation detail with nothing to tune, and a constant lets `SessionCookieFilter`, which is instantiated before `@ConfigMapping` beans are reliably resolvable, read it without an injection point.

The lifetime is the one session property that *is* configurable. It is a policy choice that varies by deployment, and it is not a weakening of the cookie.

### D3 — `SessionCookieFilter` fills `X-Subject-Id`; `AuthorizeResource` is unchanged

`SessionCookieFilter` (`tessera-rest/.../session/SessionCookieFilter.java`) runs on every tenant-scoped request, after `TenantResolutionFilter` and before `RateLimitFilter`. It resolves the session cookie to a subject through `SessionUseCase.resolveSubject` and writes that subject into `X-Subject-Id`. `AuthorizeResource` and `ConsentResource` keep reading the header exactly as before. The session is translated into the existing seam; the seam is not redesigned.

**The trust boundary.** Unless `iam.subject.trust-header` is `true` (default `false`), the filter first removes any `X-Subject-Id` the caller sent. A verified session cookie is then the only way a subject reaches a resource. Any failure to resolve the cookie (missing, malformed, unknown, expired, revoked, other baseline) leaves the header absent, and the resource refuses with `access_denied`: a `400` at `/authorize`, a `401` at `/consent`. The filter itself never answers with an error, so it cannot be used to probe whether a session exists.

`SubjectHeaderTrustBoundaryTest` pins this: a forged `X-Subject-Id` with no session cookie is refused at `/authorize` (`400 access_denied`) and at `/consent` (`401 access_denied`). `SessionSeamIntegrationTest` shows the positive path (login, then `/authorize` with only the cookie issues a code) and that an unknown cookie does not authenticate. `LogoutResourceTest` shows that a logged-out cookie no longer authenticates `/authorize`.

`trust-header=true` is an explicit escape hatch for a deployment whose own ingress asserts the header and strips any client value. Tessera cannot check that, so it is off unless an operator turns it on.

**Why a filter and not a change to `/authorize`.** It keeps one place that decides what subject a request carries, for every tenant-scoped resource, including ones added later. It leaves the tested authorization code path untouched. And it makes the header safe on a public origin (ADR-IAM-002), where there is no gateway to strip it.

### D4 — Password-only login first

`POST /login` (`LoginResource`) takes `username` and `password` as a form and returns `204` with the session cookie, or `401 invalid_credentials`. It serves no HTML.

- **Argon2id.** A password credential is a `PasswordHash`: an Argon2id PHC string carrying its own parameters and salt (`tessera-domain/.../credential/PasswordHash.java`). `Argon2PasswordCredentialVerifier` reads the parameters from the stored string, rejects absurd ones (memory above 1 GiB, more than 40 iterations, parallelism above 16) and fails closed on a malformed hash. It runs on the dedicated `argon2` worker pool, never the event loop.
- **Identical responses for unknown user and wrong password.** The verifier runs one Argon2 pass on every reject path, against a timing-equaliser hash when the user or credential is missing, so timing does not separate the cases. The port returns `empty()` for both, `LoginService` maps both to `Denied("invalid_credentials")`, and `LoginResource` renders one fixed `401` body. `LoginResourceTest.unknownUsernameDeniedIdentically` pins that both cases get the same status and error code; the timing property has no test.
- **Throttling by reuse.** `ThrottlingPasswordCredentialVerifier` is a CDI decorator on the verifier port. It applies the same `TokenBucket` failure budget, configuration (`credential-failure-burst`, default 10; `credential-refill-per-minute`, default 2) and metric as `ThrottlingClientSecretVerifier`, keyed per `(tenant, username)`. A failed verification spends budget and a successful one does not. Once the budget is spent, the decorator returns `empty()` without running Argon2, so the caller sees the same `invalid_credentials` as a wrong password: no `429`, no oracle. It is a throttle that refills, not a fixed lockout. `LoginThrottleTest` pins that a spent budget refuses even the correct password and that the budget is per tenant. `/login` is also `@RateLimited` at ingress, by source IP only (ADR-IAM-002 records why that tier is weak).

**Why password first.** It is the one credential that needs no client-side ceremony, and it completes the end-to-end flow: login, session, `/authorize`, code, token. `LoginUseCase` records the rest of the sealed `Credential` set (WebAuthn, TOTP, recovery codes) as follow-on work: each is a second verification layered on a session that already exists, not a prerequisite for one.

### D5 — Out of scope

- **MFA, WebAuthn, TOTP.** The domain models these credential kinds; no login path verifies them. Adding one is a new verifier behind the same session establishment, not a change to D2 or D3.
- **A login page hosted by tessera.** Tessera is a JSON protocol server. The relying party's own front end serves the login form and posts it to `POST /login`. The cross-origin call is permitted through `TESSERA_CORS_ORIGINS` against the deny-by-default CORS policy (ADR-IAM-002).

## Consequences

**Positive.** The `/authorize` seam is filled without touching the authorization code path. `X-Subject-Id` is safe by default on a public origin. Session state lives server-side, so logout and expiry take effect on the next request. Login does not reveal whether a username exists, by response body or by Argon2 timing. Credential guessing is bounded per account by the same mechanism that already protects client secrets.

**Negative / accepted.**

- Every request with a session cookie costs one session lookup.
- Expiry is absolute: an active user is logged out at the end of the lifetime, and an idle session lives that long. Expired rows are never deleted: nothing purges `auth_session`.
- The failure budget lives in each node's memory. A fleet of N nodes allows up to N times the budget, and a restart resets it. The server configuration notes the per-node limit.
- An attacker who knows a username can spend its budget and keep the real user out while they keep failing, bounded by the refill rate. This is the accepted cost of throttling per account.
- A consent change replaces the whole set for that client. There is no history of earlier grants.

**What would reopen each choice.**

| Choice | Reopen when |
|---|---|
| D1 per-client consent | the consent step must let a user grant some requested scopes and refuse others, or an audit needs each scope's grant time |
| D2 fixed flags | a supported topology needs the login front end on a different site from tessera (see the `SameSite` open point) |
| D2 absolute expiry | users are logged out mid-task in practice, or an idle timeout is required by policy |
| D3 header seam | a resource needs more than the subject from the session (authentication time, method, assurance level) |
| D3 default-closed header | never on its own; `trust-header=true` exists for a deployment that has verified its ingress |
| D4 password only | a deployment requires a second factor, or a relying party asks for `acr`/`amr` |
| D4 per-node throttle | more than one node serves `/login` and the per-node budget is measured as too loose |
| D5 no hosted page | relying parties keep re-implementing the same login form, or a flow needs tessera to render a page (e.g. a WebAuthn ceremony on its own origin) |

## Open points the code does not settle

These are found in the code as it stands. This record does not decide them; each needs a decision or a fix of its own.

1. **Consent is recorded but not enforced.** No production code calls `ConsentUseCase.hasConsented`. `/authorize` issues a code to any subject with a session, whether or not consent was recorded. The "at least the requested scopes" check is exercised only by `ConsentServiceTest`. D1 describes the granularity of what is stored, not a gate the flow applies today.
2. **The persistent store does not replace a consent.** The port says `grant` "records (or replaces)". `PersistentConsentStore.grant` persists a new row with a fresh id, so a second grant for the same `(tenant, baseline, user, client)` hits `uq_consent_pair` rather than replacing it. Only the in-memory `FakeConsentStore` replaces, and `SessionAndConsentTenantIsolationIT` grants only once.
3. **`SameSite=Strict` assumes the login front end is same-site with tessera.** The `SessionCookies` javadoc gives that as the reason the strict setting costs nothing. A relying-party page on another subdomain of the same registrable domain is same-site and works. On a different registrable domain, browsers can refuse to store the cookie from the cross-site `POST /login` response, and even if it is stored, the cookie is not sent on requests that the relying party's page starts. No test covers either topology.
4. **Login is tenant-scoped, not baseline-scoped.** `UserRepository.findByUsername` filters by tenant through RLS only, and `iam_user.username` has no unique constraint. A user from one baseline can therefore establish a session in another baseline of the same tenant, and a username shared across baselines makes the lookup non-unique. The session store does check the baseline (`SessionAndConsentTenantIsolationIT`); the credential lookup in front of it does not. The throttle key `(tenant, username)` has the same grain.
5. **A new login does not end earlier sessions.** Each login creates an additional session, and only `/logout` with that session's cookie revokes it. Whether a password change or an administrative action should revoke all of a subject's sessions is not addressed.
