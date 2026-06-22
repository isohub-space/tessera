# Tessera

**A standalone, developer-friendly OIDC / OAuth2 authorization server, built on
[Quarkus](https://quarkus.io) — a from-scratch alternative to Keycloak.**

Tessera issues and signs OpenID Connect / OAuth 2.0 tokens. The name is the Roman
*tessera* — a small token that proved a bearer's identity; fitting, for a service
whose whole job is issuing verifiable tokens of identity.

> **Status: early / experimental.** The cryptographic core (signing-key lifecycle,
> JWKS, OIDC discovery), the reactive multi-tenant persistence layer (users,
> clients, sessions, consents and rotating refresh-token families, each behind
> fail-closed row-level security), and the functional auth-flow domain model are in
> place. Many authorization-server
> surfaces (the full `/authorize` + `/token` grant pipeline, client registration,
> consent UI) are still on the roadmap below. Not yet recommended for production.

## Why

Keycloak is powerful but heavy: a JEE-era footprint, slow startup, and a
configuration model that resists GitOps. Tessera is an experiment in the opposite
direction — a small, reactive, cloud-native authorization server with:

- **Fast startup & low memory** — Quarkus on virtual threads; native-image friendly.
- **Strict hexagonal architecture** — a framework-free domain you can unit-test
  without booting a container, with REST/persistence kept at the edges.
- **Multi-tenancy that fails closed** — every tenant-scoped table is protected by
  PostgreSQL row-level security keyed to a per-transaction tenant id; a missing
  tenant binding makes rows invisible rather than leaking them.
- **Modern signing** — EdDSA (Ed25519) signing keys with an explicit
  `PENDING → ACTIVE → RETIRING → RETIRED` rotation lifecycle and a published JWKS.
- **A typed, functional auth flow** — authentication steps and events modelled as
  sealed types reduced by a pure state machine, so the engine is exhaustively
  checked at compile time and trivially testable.

## Architecture

A four-module hexagon plus a thin composition root, with two small vendored
libraries:

| Module | Role |
|--------|------|
| `tessera-domain` | Pure-Java domain model (auth flow, clients, tokens, signing keys). No framework imports. |
| `tessera-api` | Application contract: inbound/outbound ports + the framework-free application service. |
| `tessera-persistence` | Outbound adapter: Hibernate Reactive + reactive-pg-client; Flyway owns the schema & RLS. |
| `tessera-rest` | Inbound adapter: reactive JAX-RS resources, OpenAPI 3.1, RFC 7807 problems. |
| `tessera-server` | Composition root — the runnable Quarkus application. |
| `tessera-statemachine` | Vendored: a pure-Java typed state-machine library (the lifecycle primitive). |
| `tessera-observability` | Vendored: Micrometer/Prometheus metrics, OpenTelemetry tracing, readiness probes. |

`domain` and `api` are framework-free by construction; only `tessera-server`
depends on concrete adapters. Architectural boundaries are enforced by ArchUnit
tests in the server module and a domain-purity test in `tessera-domain`.

## Build & run

Requires **JDK 25** and **Maven 3.9+**.

```bash
# Build everything (unit tests only; integration tests need Docker — see below).
mvn -DskipITs verify

# Run in dev mode (live reload) from the composition root.
mvn -pl tessera-server quarkus:dev
```

The server listens on `http://localhost:8090` by default. Key endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | JSON Web Key Set (public signing keys) |
| `GET /q/health` · `/q/health/ready` · `/q/health/live` | Health probes |
| `GET /q/metrics` | Prometheus metrics |

### Integration tests

The `*IT` suites (row-level-security isolation, JWKS endpoint) boot against a real
PostgreSQL via [Testcontainers](https://testcontainers.org), so they require a
running Docker daemon. They run in the `verify` phase; pass `-DskipITs` to skip
them when Docker isn't available.

## Roadmap

- [ ] OAuth2 `/authorize` + `/token` endpoints (authorization-code + PKCE, client-credentials)
- [ ] Dynamic client registration (RFC 7591)
- [ ] Refresh tokens & token introspection/revocation (RFC 7662 / 7009)
- [ ] Pluggable user/credential stores and a consent UI
- [ ] Conformance against the OpenID Connect test suite
- [ ] Re-enable static analysis gates (Checkstyle / SpotBugs) in the build

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](./LICENSE). Tessera
bundles two small internal libraries; their provenance is recorded in
[`NOTICE`](./NOTICE).
