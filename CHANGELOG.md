# Changelog

All notable changes to Tessera are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning uses a `YY.MAJOR.MINOR`
scheme with one Greek-named release per named line.

## [Unreleased]

Accumulating toward the first release, `26.1.0 "Andromeda"`.

### Added
- OAuth 2.0 Authorization Code flow with mandatory PKCE (S256): `/authorize` → `/token`.
- RFC 9068 JWT access tokens and OIDC ID tokens, signed with EdDSA (Ed25519).
- Rotating, single-use refresh tokens with family reuse-detection (RFC 9700 §4.14) and a
  `grant_type=refresh_token` grant.
- OIDC discovery (`/.well-known/openid-configuration`) and JWKS endpoints, generated from the
  enforced capability set.
- Signing-key lifecycle: `PENDING → ACTIVE → RETIRING → RETIRED` with publish-before-sign
  rotation.
- Confidential (Argon2id secret) and public (PKCE) client registry, with a registered
  `redirect_uri` exact-match allow-list enforced before any code is issued.
- Multi-tenant PostgreSQL persistence with fail-closed row-level security, resolved at a single
  ingress chokepoint.
- Edge security baseline: deny-by-default CORS, security headers, TLS redirect / HSTS.
- Ingress rate limiting on `/token` and `/authorize`, and a per-`(tenant, client)`
  credential-verification throttle, with Argon2id isolated on a dedicated worker pool.
- Tamper-evident per-tenant audit log with periodically signed checkpoints.
- Observability: Micrometer/Prometheus metrics, OpenTelemetry tracing, SmallRye Health.
- Hosted sign-in page (`GET`/`POST /signin`): `/authorize` with no session validates the client
  and redirect URI, parks the request and sends the browser there, so clients on any site sign in
  on tessera's own origin. Bound to the browser by a `SameSite=Lax` cookie, protected by a
  synchronizer token and Fetch Metadata, answered at most once, with its own
  Content-Security-Policy. Parked requests live in a shared Infinispan cache, or in process under
  `singlenode`.
- RP-initiated logout (`GET`/`POST /end_session`, advertised as `end_session_endpoint`): with a
  valid `id_token_hint` (this realm's, issued within the session lifetime) it ends the session the
  browser presents, clears the session cookie and revokes the client's refresh-token families for
  the user created up to the hint, then returns to a `post_logout_redirect_uri` registered for the
  client (exact match, `state` echoed). The session cookie is `SameSite=Strict`, so a relying
  party on another site does not end tessera's session this way; its refresh tokens are still
  revoked. ID tokens now always carry `realm_tenant` and `realm_baseline`. A missing or foreign hint, a hint for
  another user than the session's, or an unregistered redirect URI is a `400` that ends nothing
  and is never redirected. Kept outside the CORS policy, like `/authorize`.

- JWT client assertion authentication (RFC 7523 §2.2) at `/introspect` and `/revoke`: a
  `private_key_jwt` or workload-identity client authenticates there exactly as at `/token`, with
  `client_assertion_type` and `client_assertion` (`client_id` optional), through the same verifier,
  the same single-use `jti` store and the same request realm, so an assertion spent at one endpoint
  is refused at the others. An assertion together with a secret is `400 invalid_request`
  (RFC 6749 §2.3). Revocation still acts only on the refresh families issued to the authenticating
  client (RFC 7009 §2.1).
  `/introspect` and `/revoke` spend their `jti`s against a replay budget of their own,
  `iam.client-assertion.introspection-replay-cache-max-entries-per-client` (default `1000` per
  client, like `/token`'s `replay-cache-max-entries-per-client`; the per-realm and total caps apply
  to each budget apart), so introspection load, which a resource server's own callers drive, can
  fill only that budget and never refuses the same client at `/token`. A resource server that
  authenticates by assertion spends one `jti` per introspection call and should cache
  introspection results rather than introspect every request.

### Security
- Fail-closed startup: a production deployment refuses the well-known development master key.
- `/introspect` admits only an authenticated confidential client (RFC 7662 §4). A public client
  presenting its `client_id`, with or without a secret, now gets `401 invalid_client`, at the same
  cost as an unknown client, so the endpoint can no longer be used to probe tokens with a public
  identifier. A resource server that introspected as a public client must be registered as a
  confidential client and present its credential. `/revoke` is unchanged: a public client may
  still revoke the tokens issued to it (RFC 7009 §2.1).

[Unreleased]: https://github.com/meta-agentic/meta-iam/commits/main
