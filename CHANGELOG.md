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

### Security
- Fail-closed startup: a production deployment refuses the well-known development master key.

[Unreleased]: https://github.com/isohub-space/tessera/commits/main
