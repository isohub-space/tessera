# ADR-IAM-005 — OIDF Basic OP conformance in CI: not until Wave 2

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-09-11 |
| Ratified | 2026-10-19 |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (fixed-tenant mode), [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (session and consent) |

---

## Background

The OIDF Basic OP conformance suite (`oidcc-basic-certification-test-plan`) drives a browser through `/authorize`. Tessera has no login page to redirect to, no `prompt`/`max_age`/`auth_time` handling, and no `/userinfo`. A run today would stall, not fail.

Facts the decision rests on:
- Basic OP is the mandatory feature set of OIDC Core §15.1. It includes `prompt` with its `none` and `login` behaviours, `max_age`, `auth_time` when requested, and a UserInfo endpoint that accepts GET and POST (§5.3).
- The suite fills pages with a scripted browser. Any page the script does not recognise waits for a human, so an unattended run stalls there. The suite cannot inject a cookie or a request header.
- Today `/authorize` with no session returns a non-redirected `400 access_denied`.
- Certification needs every test to be PASSED, REVIEW, WARNING or SKIPPED. A single FAILED or INTERRUPTED test blocks it.
- The suite verifies EdDSA signatures, so Tessera's default signing algorithm is not a problem.

## D1 — No conformance runs until the three gaps are closed

**Decision.** No conformance runs until tessera has a login page that `/authorize` redirects to, session-aware `prompt`/`max_age`/`auth_time`, and `/userinfo`. Then the suite runs self-hosted, nightly and advisory. It blocks only on a new failure against a committed list of known failures. Each release keeps a publish-for-certification archive.

**What it means.** The suite runs from a pinned image on the same Docker network as tessera, through `scripts/run-test-plan.py` with committed expected-failures and expected-skips files. This is how the OIDF runs the suite in its own CI. It is not a required PR check.

**Consequences.**
1. No conformance claim until then.
2. The harness needs:
   - a TLS-terminating proxy that sets `X-Forwarded-Proto`;
   - the issuer set to that proxy's `https://` URL;
   - fixed-tenant mode (ADR-IAM-002), so no tenant header is needed;
   - three static clients (two `client_secret_basic`, one `client_secret_post`), where first-boot provisioning creates one;
   - rate limits relaxed for the run.
3. Runtime and flakiness are measured on the first real run.

## D2 — A stub authenticator is rejected

**Decision.** Injecting a constant subject (`iam.subject.trust-header=true` behind a proxy) does not count as authentication for this profile.

**What it means.** A stub can make the happy-path tests run. It cannot tell a logged-in browser from a logged-out one, which the profile requires:
- `prompt=login` must re-authenticate a logged-in user;
- `prompt=none` must return an error such as `login_required` when the user is not logged in;
- `max_age` and `auth_time` depend on when the user authenticated.

**Consequences.**
1. The smallest legitimate implementation is:
   - a server-rendered login form that `/authorize` redirects to when there is no session;
   - a session that records when the user authenticated;
   - `prompt` and `max_age` honoured against that time;
   - `auth_time` emitted in the ID token.

## D3 — Certification is a separate product decision

**Decision.** The engineering goal is a green nightly against the known-failures list. Whether to certify a release is decided separately.

**Consequences.**
1. Certification has a fee: USD 700 per deployment for OIDF members and 3,500 for non-members, with an open-source waiver on request.
2. It also needs a signed declaration naming a software version and a responsible signer.

## Follow-ups, fixable now

- Discovery advertises `profile` and `email`, but no claims are produced.
- `client_secret_post` is accepted but not advertised.
- `POST /authorize` is unsupported.
- The default issuer port (`8080`) does not match the listen port (`8090`).
- `/userinfo` is required by the profile.

## Rejected alternatives

- **A stub authenticator.** It cannot tell a logged-in browser from a logged-out one (D2).
- **The hosted suite on every PR.** It needs a publicly reachable tessera with a real certificate on every run.
- **A required PR check.** The known-failures list starts red, so every PR would fail for reasons it did not cause.

## Open items

- Whether a publish-for-certification archive from a self-hosted suite is accepted for certification.
- Which suite setting accepts a self-signed proxy certificate.

Sources, read 2026-09-11:
- OpenID Connect Core 1.0 §3.1.2.1, §5.3 and §15.1;
- OpenID Connect Discovery 1.0;
- *OpenID Connect Conformance Profiles v3.0*;
- the OIDF conformance-suite source and wiki at `gitlab.com/openid/conformance-suite`;
- the openid.net certification pages.
