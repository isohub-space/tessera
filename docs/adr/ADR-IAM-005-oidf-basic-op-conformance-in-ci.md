# ADR-IAM-005 — OIDF Basic OP conformance in CI: not until Wave 2

| Field | Value |
|---|---|
| Status | **Proposed** — awaiting ratification. Not a decision until accepted. |
| Date | 2026-09-11 |
| Moved here | 2026-10-18, from the project's planning notes. The decision and its evidence are unchanged; references to planning items are restated as plain descriptions, and links to the other records here are added. This record supersedes an earlier unaccepted draft. |
| Spike | can the OIDF Basic OP conformance plan run in CI against Tessera (time-box 3 days nominal; this used well under one; deliverable = this record) |
| Evidence date | 2026-09-11. Tessera read at `3397096` (`fix(iam): close the X-Subject-Id authentication bypass, default-closed (#86)`), with no code changes made. OIDF conformance-suite sources read at `master` on the same day through the GitLab raw/API endpoints; spec and openid.net pages fetched the same day. |
| Affects | CI, `/authorize`, session semantics, `/userinfo`, discovery metadata, key bootstrap and provisioning |
| Relates to | [ADR-IAM-001](ADR-IAM-001-audit-checkpoint-key-custody.md) (key custody), [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (tenant tier and path-scoped issuer), [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (session and consent) |

---

## The answer

**No — not as a CI gate, not as a nightly, not even as a one-off local run that produces a
meaningful pass/fail ledger — until Wave 2 delivers an HTML login page that `/authorize`
redirects to, an `auth_time`-bearing session model that honours `prompt`/`max_age`, and a
`/userinfo` endpoint.** Everything else the suite needs is either already there, a small
defect fixable now, or harness plumbing that costs a day once those three exist.

The spike's own exit criterion allows this outcome ("if the answer is 'not until Wave 2', that is
recorded so it is not re-asked"). It is recorded here. No follow-up work is opened; §8 names
the single event that makes it worth re-opening.

A stub authentication mechanism (the `iam.subject.trust-header=true` mode plus a proxy that
injects `X-Subject-Id`) does **not** rescue the answer — see §5.3. That is the specific
question the spike asked, and the answer is: the stub makes the happy-path modules run, but the
profile's *mandatory* features (`prompt=login` re-authentication, `prompt=none` when not
logged in, `max_age`, `auth_time`) are defined by the OP being able to tell a logged-in browser
from a not-logged-in one, which a static stub cannot do by construction. It therefore cannot
turn a red ledger green; it can only hide which rows are red for a real reason.

## 1. What was verified firsthand, and what was not

Every claim below is tagged. **[T]** = read in Tessera source at `3397096`. **[S]** = read in the
conformance-suite source or wiki (GitLab, `master`, 2026-09-11). **[N]** = read in a normative
spec (OIDC Core 1.0 / Discovery 1.0, openid.net HTML, 2026-09-11). **[O]** = read on an
openid.net certification page (2026-09-11). **[?]** = not established; listed in §9 as open.
Nothing here is from memory of the suite; where a module was not opened, its row says so.

### 1.1 Corrections to the spike's premises

| Premise | Finding |
|---|---|
| "Basic OP assumes an end-user login Tessera does not have until Wave 2." | Half wrong, right in effect. Since `f382ef1` (2026-09-09, #76) Tessera **has** `POST /login` (form-urlencoded username/password → Argon2id verify → `tessera_session` cookie, HttpOnly/Secure/SameSite=Strict), `POST /consent`, `POST /logout`, and a `SessionCookieFilter` that turns the cookie into `X-Subject-Id` before `/authorize` runs. **[T]** `LoginResource`, `SessionCookies`, `SessionCookieFilter`. But: no HTML is served anywhere (`LoginResource` javadoc: "no HTML is served here … a real deployment fronts this with its own login page"), and `/authorize` with no subject returns **HTTP 400 `access_denied` JSON, never a redirect to a login page** **[T]** `AuthorizeResource` ("A request with no subject is refused … `login_required` is out of scope here"). The README's "ships no login or consent UI" (line 53) and the Wave 2 roadmap are stale as to the API and accurate as to the UI. |
| CI is one `mvn -B -ntp clean verify` job, ubuntu-latest, 30 min, Slack on failure, no services. | Confirmed **[T]** `.github/workflows/ci.yml`. Ten other workflows, none stands up a network service. |
| "The OIDF suite is externally hosted or self-hosted Docker." | Both, confirmed **[S][O]**. Hosted at `https://www.certification.openid.net/` (staging tracks `master`). Self-hosting: `docker-compose-prebuilt.yml` pulls `registry.gitlab.com/openid/conformance-suite:<IMAGE_TAG>` + its nginx + `mongo:6.0.13`; needs `localhost.emobix.co.uk → 127.0.0.1` in `/etc/hosts` or a `BASE_URL` override; UI on `:8443`. `IMAGE_TAG` pins a release "to match a previously certified test-plan version". |
| "Certification requires a publicly reachable OP with real TLS." | Not stated on any page read **[O]** — `connect_op_testing` says only to register the redirect URI `https://www.certification.openid.net/test/a/<ALIAS>/callback` on the OP, which implies the *hosted* suite must reach the OP. For a *self-hosted* run the OIDF's own GitLab CI proves the opposite: `docker-compose-localtest.yml` runs the suite against `panvafs/oidc-provider-oidc-core-sample` on a private docker network with issuer `https://oidcc-provider:3000` and a self-signed cert, headless, every pipeline **[S]** `.gitlab-ci.yml` `oidcc_test` job, `.gitlab-ci/run-tests.sh --local-provider-tests`. Whether a "Publish for certification" zip produced by a self-hosted instance is accepted for certification is **[?]** (§9). |
| Existing ITs are Testcontainers/Postgres only. | Confirmed **[T]** — nine `*IT.java`, all Postgres; `tessera-server`'s only IT is `JwksEndpointIT`. There is no `tessera-e2e` module despite the README naming it as the release gate. |

### 1.2 What the Basic OP profile actually is

- The profile document **[O]** *OpenID Connect Conformance Profiles v3.0* (2018-06-28) §2.1.1:
  Basic OP = "the Mandatory to Implement Features for All OpenID Providers described in
  Section 15.1 of OpenID Connect Core 1.0", tested by the rows marked `y` in its §3.1 table.
- OIDC Core §15.1 **[N]**, verbatim list: RS256 ID-token signing "unless the OP only supports
  returning ID Tokens from the Token Endpoint (as is the case for the Authorization Code Flow)
  and only allows Clients to register specifying `none`"; `prompt` "including the specified user
  interface behaviors such as `none` and `login`"; `display` (must not error); `ui_locales` /
  `claims_locales` (must not error); `auth_time` "when requested"; `max_age` enforcement;
  `acr_values` (must not error).
- OIDC Core §3.1.2.1 **[N]**: `nonce` is **OPTIONAL** in the code flow; `state` is
  RECOMMENDED; "The Authorization Server MUST attempt to Authenticate the End-User in the
  following cases: The End-User is not already Authenticated; The Authentication Request
  contains the prompt parameter with the value login." `prompt=none`: "An error is returned if
  an End-User is not already authenticated … typically `login_required`".
- OIDC Core §5.3 **[N]**: the UserInfo endpoint "MUST support the use of the HTTP GET and HTTP
  POST methods" and "MUST accept Access Tokens as OAuth 2.0 Bearer Token". OIDC Discovery §3
  **[N]**: `userinfo_endpoint` is RECOMMENDED (not REQUIRED) metadata — but the Basic OP table
  marks `OP-UserInfo-Endpoint` `y` **[O]**, so a Basic OP must have one.
- OIDC Discovery §4.3 **[N]**: "The issuer value returned MUST be identical to the Issuer URL
  that was used as the prefix to `/.well-known/openid-configuration`".
- The plan the suite runs is `oidcc-basic-certification-test-plan` (display name "OpenID
  Connect Core: Basic Certification Profile Authorization server test") **[S]**
  `OIDCCBasicTestPlan.java`. It fixes variants `response_type=code`,
  `client_auth_type=client_secret_basic`, `response_mode=default`, and leaves
  `ClientRegistration` (static vs dynamic) and `ServerMetadata` (discovery vs static) to the
  tester. The full module list is the ledger in §6.
- Pass rule **[O]** `connect_op_testing`: "Certification of a profile requires that you have
  'PASSED', 'REVIEW', 'WARNING' or 'SKIPPED' results for all tests in the profile. You cannot
  certify with any FAILED or INTERRUPTED results."
- Clients **[O]**: without dynamic registration "you are required to manually register three
  clients": two `client_secret_basic` (the second "to test that authorization codes are
  correctly bound to a client"), one `client_secret_post` (may be the first if the server
  permits both).

### 1.3 How the suite drives an OP (the part that decides this spike)

- Every OP test module sends a Selenium/HtmlUnit browser to the authorization endpoint
  **[S]** wiki `Design/BrowserControl`. Automation is a `browser` block in the test config:
  a URL `match`, then `tasks`, each with its own `match` and a `commands` list of
  `["text"|"click"|"wait", "id"|"name"|"xpath"|"css"|"class", selector[, value]]`. "It's
  required that task lists always include a verification task … to ensure all redirects and
  other items return as expected — if this is missing tests may randomly fail."
- "Any URLs … that do NOT match any browser control objects will be placed into a queue and
  exposed in the UI for user interaction." I.e. an unattended run **stalls** on any page the
  script does not recognise. **[S]**
- There is **no cookie-injection or header-injection command** in the documented set, and
  none in `BrowserControl.doCommand` beyond the documented ones plus image-placeholder
  actions **[S]** `BrowserControl.java` (`update-image-placeholder`, `-optional`). Cookies
  are held in one HtmlUnit `CookieManager` per test-module instance, so a login in the first
  authorization of a two-authorization module persists into the second. **[S]**
- The suite's outbound HTTP (discovery, token, userinfo) is plain HTTP from the Java process;
  the config model is `server.discoveryUrl` **or** static `server.issuer / jwks_uri /
  authorization_endpoint / token_endpoint / userinfo_endpoint`, and `client.client_id /
  client_secret` (static) or dynamic registration **[S]** `AbstractOIDCCServerTest`
  `@VariantConfigurationFields`, wiki `Design/Configuration`. No facility to add a custom
  request header (such as Tessera's `X-Tenant-Id`) was found in either **[S]**.
- The suite verifies **EdDSA** ID-token signatures: `AbstractVerifyJwsSignature` special-cases
  `Curve.Ed25519` → `new Ed25519Verifier(publicKey)` **[S]**. So Tessera's default signing
  algorithm is not a blocker.
- The suite has a trust-all `SSLContext` + `NoopHostnameVerifier` path in its HTTP client
  **[S]** `AbstractCondition.java` ~L678–702; the condition that enables it was not read
  **[?]**. OIDF's own CI runs against a self-signed OP, so *some* configuration works.
- CI driver **[S][O]**: `scripts/run-test-plan.py <plan> <config.json>` with
  `--expected-failures-file`, `--expected-skips-file`, `--export-dir`, `--no-parallel`; the
  OIDF page *About the conformance suite* says "it is highly recommended that authorization
  server developers integrate this into their development pipeline". The expected-failures
  file is how the OIDF itself encodes tolerated red rows: the run exits non-zero only on
  *unexpected* failures/warnings.

## 2. Tessera's surface, as it stands

Endpoints **[T]** (grep of `@Path`): `/.well-known/openid-configuration`, `/jwks` **and**
`/.well-known/jwks.json`, `GET /authorize`, `POST /token`, `POST /introspect`, `POST /revoke`,
`POST /login`, `POST /consent`, `POST /logout`. **There is no `/userinfo` resource.**

`OidcCapabilities.enforced()` **[T]**: `response_types=[code]`,
`grant_types=[authorization_code, refresh_token]`, `code_challenge_methods=[S256]`,
`token_endpoint_auth_methods=[client_secret_basic, private_key_jwt, tls_client_auth]`,
`subject_types=[public]`, `id_token_signing_alg=[EdDSA, ES256]` (from `SigningAlgorithm`),
`dpop_signing_alg=[ES256]`, `scopes=[openid, profile, email]`, cert-bound tokens `true`.

`DiscoveryDocument.forIssuer` **[T]** derives `authorization_endpoint`, `token_endpoint`,
`userinfo_endpoint` (= issuer + `/userinfo`) and `jwks_uri` (= issuer + `/jwks`)
**unconditionally from the issuer string**, not from the capability record.

Every endpoint above, discovery and JWKS included, is `@TenantScoped`; `TenantResolutionFilter`
aborts with 400 before the handler when `X-Tenant-Id` is missing or malformed **[T]**. So a
standards-conformant RP's opening `GET /.well-known/openid-configuration` gets a 400 and stops.
For a test rig that is harness plumbing (the tenant-injecting proxy of §3); for a production
deployment it is an open question (§9.8).

ID token claims **[T]** `IssuedTokenClaims`: `iss, sub, aud, iat, exp, nonce` — no `auth_time`.
`AuthorizeResource` **[T]** binds only `response_type, client_id, redirect_uri, scope, state,
nonce, code_challenge, code_challenge_method`; it requires `state` and `nonce` (400
`invalid_request` otherwise), ignores every other parameter, and is `@GET` only.

Signing keys **[T]**: `KeyRotationService.mintPending/promoteToActive` are called from **tests
only** (`SigningKeyPipelineIT`, `JwksEndpointIT`); no runtime, startup or admin path mints a key.
The `%dev` seed (`V900__dev_seed.sql`) inserts a public JWK placeholder
(`"x":"dev-placeholder-public-key"`) with no private material. `SigningKeyBeans` refuses the
default master key in `LaunchMode.NORMAL`. No user/client/credential provisioning endpoint
exists; `iam_user`/`iam_credential`/`oauth_client` are seeded only by tests.

Security headers **[T]** `application.properties`: CSP `default-src 'none'; … form-action
'none'`; `%prod` forces HTTPS redirect and HSTS; issuer default `http://localhost:8080` while
the server listens on `8090`.

## 3. Run shape — decided: self-hosted, when the time comes

**Self-hosted** (`docker-compose-prebuilt.yml`, `IMAGE_TAG` pinned), on the same docker network
as Tessera, exactly the shape OIDF uses for its own regression job. Reasons: no public
reachability or real certificate needed; reproducible against a pinned suite version; runs on a
GitHub-hosted runner (Docker is present; `ci.yml` already relies on it for Testcontainers).

What the self-hosted shape requires **[S][T]**:

| Need | Why | Who provides it |
|---|---|---|
| A hostname the suite advertises (`BASE_URL`, default `https://localhost.emobix.co.uk:8443`) resolvable from Tessera's container and the runner | The redirect URI the suite registers is `<BASE_URL>/test/a/<alias>/callback`; Tessera must be able to redirect the browser there | compose network alias (the prebuilt compose already aliases `localhost.emobix.co.uk` onto nginx) |
| A TLS-terminating reverse proxy in front of Tessera that (a) presents a cert the suite's JVM accepts, (b) sets `X-Forwarded-Proto`, (c) **injects `X-Tenant-Id: <uuid>`** on every request | Tessera's discovery/JWKS/authorize/token all 400 without a tenant; `%prod` redirects plain HTTP; `Secure` session cookie is only sent over TLS | harness (nginx sidecar); none of this exists in Tessera |
| `TESSERA_OIDC_ISSUER` **and** `iam.keys.issuer` both set to the proxy's `https://` URL | Discovery §4.3 issuer-must-match; the two properties are not wired together (the properties file says so) | harness config |
| An ACTIVE signing key with private material, a tenant, an `oauth_client` ×2 (basic) + 1 (post) with the suite's redirect URI, an `iam_user` with an Argon2id `PASSWORD_HASH` credential | Nothing at runtime mints or seeds these | harness — today only by reusing test code / hand SQL |
| `iam.ratelimit.enabled=false` or raised caps | The suite fires ~40 modules, several with two authorizations each, against `/authorize` (60/min default) and `/token` (20/min default) | harness config |

**Hosted service**: only relevant for a certification submission (§7). It needs a publicly
reachable Tessera with a real certificate and the same proxy; it cannot run per-PR.

## 4. CI shape — decided: none today; nightly-advisory-with-ledger when unblocked

- **Today:** none. There is no login page for the browser to log in on, so every module in
  §6 that involves a browser ends in the "queued for user interaction" state, not in a
  verdict. A run today would not produce a ledger, only a stall.
- **When §8 is met:** a separate workflow (`workflow_dispatch` + nightly cron, **not** a
  required PR check), `docker compose` of suite + proxy + Postgres + Tessera, driven by
  `run-test-plan.py oidcc-basic-certification-test-plan <config.json>` with a committed
  `expected-failures.json` / `expected-skips.json`. Gate semantics: **blocking on regressions
  against the committed ledger, advisory on the ledger's contents** — the mechanism the OIDF
  uses on itself. That answers the spike's "does a conformance failure block a PR?": no; a
  *new* failure blocks the nightly, and the ledger shrinks by PRs that remove entries.
- **Release-time:** an immutable plan run + "Publish for certification" zip as a release
  artefact, whether or not certification is pursued (§7).
- **Runtime and flakiness: not measured.** No harness run was attempted inside the time-box
  because §8 makes any measurement today a measurement of a stall. The only datum: the OIDF's
  own pipeline runs the OIDCC plans as a dedicated docker-compose job with
  `--no-parallel-for-no-alias` "to avoid overwhelming server early on" **[S]** — i.e. they
  serialise, and they keep 500 MB of container logs "as there's no other way to see results on
  the CI". Selenium plus a 40-module plan is not a sub-5-minute job; the number must come from
  the first real run, and it belongs to the follow-up work, not here.

## 5. Capability gaps, defects, and the stub question

### 5.1 Capability gaps (the profile requires them; Tessera lacks them; roadmap wave named)

| Gap | Profile requirement | Tessera today [T] | Wave |
|---|---|---|---|
| **G1 — Browser-reachable login page.** `/authorize` must redirect an unauthenticated user agent to a page the suite's `browser` script can fill and submit, then back through `/authorize`. | Every module (BrowserControl drives `/authorize`) | 400 JSON; `POST /login` exists but is unreachable from the redirect chain; CSP `form-action 'none'` would block a form even if one were served | **Wave 2** — "Login and consent UI (server-side rendered; replaceable)" |
| **G2 — Session-aware `prompt` / `max_age` / `auth_time`.** `prompt=none` without a session → redirect with `login_required`; `prompt=login` → re-authenticate; `max_age` → enforce and emit `auth_time`. | §15.1 mandatory; modules `oidcc-prompt-none-not-logged-in`, `-logged-in`, `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-max-age-10000` | `prompt`/`max_age` unread; no `auth_time`; no-subject → non-redirected 400 `access_denied` | **Wave 2** (session model exists since #76; the authenticated-at instant and the parameters are not modelled) |
| **G3 — `/userinfo`** (GET + POST, bearer, returns `sub` and the claims for `profile`/`email`). | `OP-UserInfo-Endpoint` `y`; modules `oidcc-userinfo-get`, `-post-header`, `-post-body`, `oidcc-scope-profile`, `-email`, `oidcc-claims-essential` | Advertised in discovery, not implemented | Not on the roadmap by name. It is the natural companion of the Wave 2 login work (claims need a subject repository), in its scope or as a sibling |
| **G4 — Runtime key bootstrap + provisioning.** Some non-test path must produce an ACTIVE signing key with private material, and clients/users/credentials must be creatable. | Harness precondition, not a profile row | Tests only; dev seed is a placeholder | Key part: key custody, [ADR-IAM-001](ADR-IAM-001-audit-checkpoint-key-custody.md). Provisioning: Wave 3 "Realm management API" |

### 5.2 Defects (spec-level, fixable now, independent of any wave)

| Defect | Evidence | Effect on the plan |
|---|---|---|
| **D1 — `nonce` required in the code flow.** | `AuthorizeResource`: "nonce is required" 400 **[T]**; §3.1.2.1 `nonce` OPTIONAL **[N]** | `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` FAILS by design |
| **D2 — Discovery lies: `userinfo_endpoint` advertised with no endpoint.** `DiscoveryDocument.forIssuer` derives it from the issuer, bypassing `OidcCapabilities`. | **[T]** | Turns G3's modules from SKIP/absent into hard FAIL; violates the "Discovery never lies" invariant for the first time an external validator would notice |
| **D3 — Discovery lies (the other way): `scopes_supported=[openid, profile, email]` but no claims are ever produced.** | `IssuedTokenClaims` **[T]**; `AbstractOIDCCReturnedClaimsServerTest.skipTestIfScopesNotSupported` skips a scope test only when `scopes_supported` omits the scope **[S]** | `oidcc-scope-profile` / `-email` FAIL instead of SKIP. Honest discovery would make them SKIP (acceptable for certification) — but `OP-UserInfo-Endpoint` stays `y`, so this only shortens the red list, it does not clear it |
| **D4 — `client_secret_post` accepted but not advertised.** `TokenResource` reads `client_id`/`client_secret` from the body **[T]**; `token_endpoint_auth_methods_supported` omits it **[T]** | No module checks this; it is the invariant's spirit, and the profile *requires* a `client_secret_post` client (§1.2) — the suite will use it and it will work |
| **D5 — `POST /authorize` unsupported** (`@GET` only). | **[T]**; `oidcc-ensure-post-request-succeeds` expects the redirect to be called, result WARNING if not **[S]** | WARNING at best; in an unattended run the browser lands on a 405 page the script does not match → stall **[?]** |
| **D6 — Issuer default `http://localhost:8080` vs port `8090`; `iam.oidc.issuer` and `iam.keys.issuer` unwired.** | `application.properties` **[T]** | Configuration, not code; listed because Discovery §4.3 makes the mismatch a hard FAIL in `oidcc-discovery-*` style checks and the base flow |

### 5.3 The stub question, answered

*"Whether an end-user authentication step is required by the profile, and if so what the
minimum legitimate implementation is (a stub is either acceptable to the profile or it is
not — say which)."*

Required: yes. §15.1 **[N]** makes `prompt` (with `none` and `login` behaviours), `max_age`
and `auth_time` mandatory for **all** OPs, and the Basic OP table marks the corresponding
rows `y` **[O]**. Those three features are *definitions of the OP's behaviour relative to an
authenticated session*: "MUST reauthenticate the End-User even if the End-User is already
authenticated", "MUST NOT display any authentication or consent user interface pages … An error
is returned if an End-User is not already authenticated". An authentication step that is a
constant (a proxy-injected `X-Subject-Id`, or a pre-seeded cookie if the suite could seed one —
it cannot, §1.3) makes the OP unable to satisfy those sentences, so the modules that test them
fail regardless of the stub's quality, and they are certification-blocking (FAILED, not
WARNING) **[S]** `CheckIdTokenAuthTimeClaimPresentDueToMaxAge` FAILURE,
`CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface` FAILURE.

No OIDF page read states a policy on stubs; none is needed. The minimum legitimate
implementation is therefore the smallest thing that satisfies §15.1: a server-rendered login
form (username/password is enough — the suite types into `id`/`name` selectors) that
`/authorize` redirects to when there is no session, a session record carrying
`authenticated_at`, `prompt=login` forcing that form even with a session, `prompt=none`
redirecting with `login_required` when there is none, `max_age` compared against
`authenticated_at`, and `auth_time` emitted in the ID token when `max_age` was sent. That is
G1 + G2, i.e. Wave 2's login work plus a small session-semantics extension — not a stub.

Ruling recorded: **a stub is not acceptable for this profile**, because the profile's mandatory
rows cannot pass under one, not because a rule forbids it.

## 6. Module ledger — `oidcc-basic-certification-test-plan` against Tessera `3397096`

Assumptions: `ClientRegistration=static_client` (Tessera has no dynamic registration; the
Wave 3 RFC 7591 item), `ServerMetadata=discovery` behind the tenant-injecting proxy of §3,
and — hypothetically — G1 solved so that a browser run reaches a verdict at all. Without G1
every browser-driven row below reads "stall", which is why this is a hypothetical ledger and
not a measured one. "Verified" = the module's source was opened; "expected" = inferred from a
base class or the plan comment only.

| Module (plan order) | Outcome | Reason | Class |
|---|---|---|---|
| `oidcc-server` | PASS | happy path; base flow does not call userinfo; `ExtractAtHash`/`CHash` INFO for code flow; `EnsureIdTokenDoesNotContainNonRequestedClaims` WARNING-only. Verified | — (needs G1) |
| `oidcc-response-type-missing` | REVIEW | 400 JSON page; module accepts an error page + screenshot ("must display an error … a screenshot of which should be uploaded"). Verified | — |
| `oidcc-idtoken-signature` | SKIP | `@VariantNotApplicable(static_client)`. Verified. (Under dynamic registration it would require RS256 — `EnsureIdTokenSignatureIsRS256` FAILURE; Tessera signs EdDSA/ES256 only) | Wave 3 exposes this |
| `oidcc-idtoken-unsigned` | SKIP | `@VariantNotApplicable(static_client)`; also skipped when `none` not advertised. Verified | — |
| `oidcc-userinfo-get` | **FAIL** | `CallUserInfoEndpoint` stop-on-failure; no endpoint. Verified | G3 / D2 |
| `oidcc-userinfo-post-header` | **FAIL** | same base (`AbstractOIDCCUserInfoTest`). Verified base | G3 / D2 |
| `oidcc-userinfo-post-body` | **FAIL** | same; profile says "Warning if broken" for the *body* method, but the endpoint's absence fails earlier. Verified base | G3 / D2 |
| `oidcc-ensure-request-without-nonce-succeeds-for-code-flow` | **FAIL** | Tessera 400 `invalid_request` "nonce is required". Verified | **D1** |
| `oidcc-scope-profile` | **FAIL** | `scopes_supported` says profile → not skipped → userinfo call fails. Verified base | G3 / D3 |
| `oidcc-scope-email` | **FAIL** | same | G3 / D3 |
| `oidcc-scope-address` | SKIP | address not in `scopes_supported`. Verified base | — |
| `oidcc-scope-phone` | SKIP | same | — |
| `oidcc-scope-all` | SKIP | requires all four; `SetScopeInClientConfigurationToOpenIdEmailPhoneAddressProfile` then skip. Verified | — |
| `oidcc-alternate-happy-flow` | PASS | expected (not opened) | needs G1 |
| `oidcc-display-page` | PASS | parameter ignored, "must not result in an error" is the bar. Expected | needs G1 |
| `oidcc-display-popup` | PASS | same. Expected | needs G1 |
| `oidcc-prompt-login` | **FAIL** | `ExpectSecondLoginPage` stop-on-failure: Tessera cannot force re-auth. Verified | **G2** |
| `oidcc-prompt-none-not-logged-in` | **FAIL** | expects a *redirect* carrying a UI-required error; Tessera returns non-redirected 400 `access_denied`. Verified | **G2** |
| `oidcc-prompt-none-logged-in` | PASS | second authorization with the cookie still in the HtmlUnit jar; sub consistency only. Verified summary | needs G1 |
| `oidcc-max-age-1` | **FAIL** | `CheckIdTokenAuthTimeClaimPresentDueToMaxAge` FAILURE + second login page expected. Verified | **G2** |
| `oidcc-max-age-10000` | **FAIL** | `auth_time` must be present after `max_age=15000`. Verified | **G2** |
| `oidcc-ensure-request-with-unknown-parameter-succeeds` | PASS | JAX-RS ignores unbound query params. Verified summary | needs G1 |
| `oidcc-id-token-hint` | PASS | expected (not opened) | needs G1 |
| `oidcc-login-hint` | PASS | expected (not opened) | needs G1 |
| `oidcc-ui-locales` | PASS | expected (not opened) | needs G1 |
| `oidcc-claims-locales` | PASS | expected (not opened) | needs G1 |
| `oidcc-ensure-request-with-acr-values-succeeds` | PASS | expected (not opened) | needs G1 |
| `oidcc-codereuse` | PASS | second redemption → `TokenService` consume-exactly-once → `INVALID_GRANT` → 400 JSON; `ServerAllowedReusingAuthorizationCode` WARNING-only. Verified both sides | — |
| `oidcc-codereuse-30seconds` | PASS | same mechanism (code TTL 2 min in tests; default per `AuthFlowConfig`). Expected | — |
| `oidcc-ensure-registered-redirect-uri` | REVIEW | non-redirected 400 error body; module accepts an error page. Verified | — |
| `oidcc-ensure-post-request-succeeds` | WARNING / stall | `@GET` only. Verified | **D5** |
| `oidcc-server-client-secret-post` (variant) | PASS | body credentials accepted. Verified `TokenResource` | D4 (advertise it) |
| `oidcc-request-uri-unsigned-supported-correctly-or-rejected-as-unsupported` | SKIP | `@VariantNotApplicable(static_client)`. Verified | — |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | SKIP | "skipped if the server discovery document does not indicate support for unsigned request objects"; Tessera advertises no `request_object_signing_alg_values_supported`. Verified summary | — |
| `oidcc-claims-essential` | **FAIL** | `AbstractOIDCCReturnedClaimsServerTest` → userinfo. Verified | G3 |
| `oidcc-ensure-request-object-with-redirect-uri` | SKIP (expected) | same precondition family as the two above; the OIDF's own expected-skips list skips it for Authlete. Summary truncated — **[?]** | — |
| `oidcc-refresh-token` | PASS | refresh tokens issued; `offline_access` only requested if advertised (it is not); cross-client reuse rejected by `RefreshService`. Verified summary + `RefreshService` javadoc | — |
| `oidcc-ensure-request-with-valid-pkce-succeeds` | PASS | PKCE S256 is the only path. Expected | needs G1 |

Tally (hypothetical, G1 solved): **12 FAIL** (G2 ×5, G3/D2/D3 ×6, D1 ×1), 1 WARNING/stall
(D5), 2 REVIEW, 8 SKIP, 16 PASS (all but three of the PASSes need G1). Without G1: no ledger.
Certification-blocking today: every FAIL row; all of them are G2, G3 or D1.

> **Nothing in this tally was observed. No suite instance was ever started and no module was
> ever run** — the numbers are predictions derived from reading module sources and base
> classes, under the stated assumptions (static client, discovery behind the tenant-injecting
> proxy of §3, and G1 hypothetically solved). Rows marked "expected" were not even opened;
> §9.7 lists them. Against Tessera as it actually stands the whole table collapses to a single
> outcome — the suite stalls before any module reaches a verdict — and the correct summary of
> a real run today is "no ledger", not "12 FAIL". Do not quote these counts as results.

**What this means for the login-page work.** Closing G1 does not make conformance pass; it
makes it *measurable*. On the tally above, a Tessera with a redirect-reachable login page still
fails twelve modules, because G2 (`prompt`/`max_age`/`auth_time`) and G3 (`/userinfo`) are
untouched by it. That work therefore buys observability, not conformance, and a
conformance-based justification for it does not hold. A "the product needs a login UI to be a
usable IdP" justification stands on its own and is unaffected by any of this.

## 7. Certification vs. passing locally — an honest statement

- **Fees [O]** `certification/fees`: OpenID Connect certification is **$700 USD per new
  deployment for members, $3,500 for non-members**, covering "as many profiles as they choose
  within a calendar year" for that deployment. An **open-source fee waiver** exists on request
  to `certification@oidf.org`, conditioned on "none of the primary maintainers … are being
  compensated by an employer for their work on the project" **[O]**
  `open-source-project-certification-policy`; "Not all open source projects will qualify".
- **Process [O]** `how-to-submit-your-certification-request`: an immutable test plan, the
  "Publish for certification" zip, a payment code, a form at `submissions.openid.net`, and a
  DocuSign-signed *Certification of Conformance* naming a **software version** and a
  responsible signer; the OIDF checklist **[S]** reviews every REVIEW screenshot for factual
  correctness of error pages and checks the plan version is "close enough" to the current
  suite release.
- **Therefore:** certification is a product decision with a spend, a signer, and a named
  release; it cannot precede a Wave-2-complete Tessera because the FAIL rows in §6 are all
  certification-blocking. **Passing the plan locally (a green nightly against the ledger) is
  the engineering goal**, and it is what an "OIDF Basic OP conformance target" should mean.
  Whether to pursue the badge for `26.1.0 "Andromeda"` or later is a product decision and is
  explicitly **not** decided here.

## 8. What must be true before this question is worth re-opening

Re-open **when a server-rendered login page that `/authorize` redirects to when no session
exists is merged** — that is G1, and it is the only gap that turns "stall" into "ledger". At
that point open one follow-up item: *"Stand up the OIDF Basic OP harness as a
`workflow_dispatch`/nightly job with a committed expected-failures ledger"*, sized against
these prerequisites:

1. G1 — login page reachable by redirect; CSP `form-action` relaxed to `'self'` for it.
2. G4 (key part) — a non-test path to an ACTIVE signing key with private material, which is
   the same problem the key-custody record ([ADR-IAM-001](ADR-IAM-001-audit-checkpoint-key-custody.md))
   decides; the harness cannot precede that decision.
3. G4 (data part) — a seed path for tenant, three clients, one user with a password credential
   (SQL in a Flyway `db/harness` location is enough; no API needed).
4. The proxy of §3 (nginx: TLS, `X-Forwarded-Proto`, `X-Tenant-Id`).
5. D1, D2, D6 fixed first (each is under a day and shrinks the initial ledger without waiting
   for G2/G3): make `nonce` optional in the code flow; derive `userinfo_endpoint` (and
   `client_secret_post`) from `OidcCapabilities` so discovery stops lying; align the issuer
   default with the port or remove the default.

G2 and G3 are not prerequisites for *running* the harness — they are the ledger's initial
contents. They are prerequisites for a *green* ledger and for certification.

## 9. Open questions (not established; do not treat as facts)

1. Whether a "Publish for certification" package produced by a **self-hosted** suite instance
   is accepted for certification, or only packages from `www.certification.openid.net`. Not
   stated on any page read; the checklist verifies plan immutability and version, which a
   self-hosted instance can also produce.
2. Under what configuration the suite's trust-all TLS path (`AbstractCondition` ~L678) is
   active — i.e. whether a self-signed proxy certificate in front of Tessera "just works" or
   needs a CA import into the suite container.
3. Unattended behaviour when a browser task does not match: the wiki says the URL is queued
   for a human; the timeout after which the module is marked INTERRUPTED was not read.
4. Runtime per plan run and flakiness rate: **not measured**; no run was possible.
5. Whether `state` being *required* by Tessera (spec: RECOMMENDED) trips any Basic module. No
   module in the plan was seen to omit `state`; not exhaustively checked.
6. §15.1's RS256 MUST: the exception needs "only allows Clients to register specifying `none`",
   which Tessera (no registration at all) neither meets nor violates. The suite skips the
   RS256 module for static clients, so it does not bite for certification under static
   registration; it would bite the moment dynamic registration (Wave 3) is offered.
7. Modules marked "expected (not opened)" in §6: `oidcc-alternate-happy-flow`,
   `oidcc-display-*`, `oidcc-id-token-hint`, `oidcc-login-hint`, `oidcc-ui-locales`,
   `oidcc-claims-locales`, `oidcc-ensure-request-with-acr-values-succeeds`,
   `oidcc-codereuse-30seconds`, `oidcc-ensure-request-with-valid-pkce-succeeds`,
   `oidcc-ensure-request-object-with-redirect-uri`. Their PASS/SKIP rows are inferences from
   plan comments and base classes.
8. **How a standards-conformant RP addresses one realm in production.** Carried forward from
   the earlier draft this record supersedes, which raised it without answering it. §3 solves
   tenancy for the *test rig* by putting an `X-Tenant-Id`-injecting proxy in front of Tessera.
   That is legitimate for a harness and settles nothing for a real deployment: every endpoint
   including discovery and JWKS is `@TenantScoped`, and a conformant RP sends standard headers
   only. The candidates, each with consequences far beyond conformance, are a per-tenant
   hostname mapped to a realm at the edge; a per-tenant path prefix; or a conformance-only
   single-tenant deployment profile — the last being the cheapest and the least honest, since
   it would certify a configuration nobody runs. **This is a product question, it was not
   answered at the time of this record, and it is not made moot by closing G1–G4.**
   [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (2026-09-23, Proposed)
   later proposes a path-scoped issuer, which bears on it.

## 10. Sources actually read

Tessera `3397096`: `README.md`, `.github/workflows/ci.yml`,
`tessera-server/src/main/resources/application.properties`,
`tessera-domain/.../oidc/OidcCapabilities.java`, `.../oidc/DiscoveryDocument.java`,
`.../signingkey/SigningAlgorithm.java`, `.../authcode/IssuedTokenClaims.java`,
`tessera-rest/.../AuthorizeResource.java`, `TokenResource.java`, `DiscoveryResource.java`,
`JwksResource.java`, `login/LoginResource.java`, `login/LoginConfig.java`,
`consent/ConsentResource.java`, `session/SessionCookieFilter.java`,
`session/SessionCookies.java`, `tenancy/TenantResolutionFilter.java`,
`tenancy/TenantHeaders.java`, `config/OidcDiscoveryConfig.java`,
`tessera-api/.../TokenService.java`, `tessera-persistence/.../KeyRotationService.java`,
`SigningKeyConfig.java`, `SigningKeyBeans.java`, `UserRepository.java`,
`credential/Argon2PasswordCredentialVerifier.java`, Flyway `V1`–`V6`, `V900__dev_seed.sql`,
`tessera-server/src/main/docker/Dockerfile.jvm`, commit `f382ef1` (#76) message and stat.

OIDF conformance-suite (`gitlab.com/openid/conformance-suite`, `master`, 2026-09-11):
`README.md`; wiki `home`, `Developers/Build-&-Run`, `Design/BrowserControl`,
`Design/Configuration`, `Certification-Check-List`, `Continuous-Integration-&-Deployment`;
`docker-compose-prebuilt.yml`, `docker-compose-localtest.yml`, `.gitlab-ci.yml` (oidcc jobs),
`.gitlab-ci/run-tests.sh`, `expected-skips-oidcc.json`, `local-provider-oidcc.json`,
`scripts/run-test-plan.py` (argument parser); `openid/OIDCCBasicTestPlan.java`,
`OIDCCTestPlan.java`, `AbstractOIDCCServerTest.java`, `OIDCCServerTest.java`,
`AbstractOIDCCUserInfoTest.java`, `AbstractOIDCCReturnedClaimsServerTest.java`,
`AbstractOIDCCAuthCodeReuse.java`, and the modules named "Verified" in §6;
`condition/client/AbstractVerifyJwsSignature.java`, `frontchannel/BrowserControl.java`,
`condition/AbstractCondition.java` (grep only).

Normative: OpenID Connect Core 1.0 §3.1.2.1, §5.3, §15.1, §15.2; OpenID Connect Discovery 1.0
§3, §4.3. OIDF pages: `/certification/`, `/certification/fees/`,
`/certification/connect_op_testing/`, `/certification/about-conformance-suite/`,
`/certification/open-source-project-certification-policy/`,
`/how-to-submit-your-certification-request/`; *OpenID Connect Conformance Profiles v3.0* pp. 1–6.
