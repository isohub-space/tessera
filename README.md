# Tessera

**A standalone, developer-friendly OIDC / OAuth2 authorization server, built on
[Quarkus](https://quarkus.io) — a from-scratch alternative to Keycloak.**

Tessera issues and signs OpenID Connect / OAuth 2.0 tokens. The name is the Roman
*tessera* — a small token that proved a bearer's identity; fitting, for a service
whose whole job is issuing verifiable tokens of identity.

> **Status: early / experimental.** The cryptographic core (signing-key lifecycle,
> JWKS, OIDC discovery), the reactive multi-tenant persistence layer (users,
> clients, sessions, consents and rotating refresh-token families, each behind
> fail-closed row-level security), the functional auth-flow domain model, and the
> **Authorization Code flow with mandatory PKCE (S256)** — `/authorize` →
> `/token`, issuing signed RFC 9068 JWT access tokens and OIDC ID tokens — are in
> place. Other authorization-server surfaces (client registration,
> refresh/introspection/revocation, a login/consent UI, the remaining grants) are
> still on the roadmap below. Not yet recommended for production.

## Why

Keycloak is powerful but heavy: a JEE-era footprint, slow startup, and a
configuration model that resists GitOps. Tessera is an experiment in the opposite
direction — a small, reactive, cloud-native authorization server with:

- **Fast startup & low memory** — Quarkus on virtual threads; native-image friendly.
- **Strict hexagonal architecture** — a framework-free domain you can unit-test
  without booting a container, with REST/persistence kept at the edges.
- **Multi-tenancy that fails closed** — every tenant-scoped table is protected by
  PostgreSQL row-level security keyed to a per-transaction tenant id; a missing
  tenant binding makes rows invisible rather than leaking them. The caller's
  tenant is resolved once, at the request edge, from a gateway-asserted
  `X-Tenant-Id` header into a request-scoped tenant context (never inferred from
  the request body); a request that carries no resolvable tenant is rejected before
  it reaches a handler.
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

## Observability

Tessera ships first-class observability in the `tessera-observability` module; the
composition root inherits it simply by depending on the module.

- **Metrics** — Micrometer with a Prometheus registry on `GET /q/metrics`. Every
  application meter follows one convention, `iam.<subsystem>.<metric>` (rendered by
  Prometheus as e.g. `iam_server_started_total`), produced through a single naming
  authority so the convention is applied in exactly one place. Wired out of the box:
  `iam.server.started` / `iam.server.uptime` (lifecycle), `iam.key.active` (the count
  of `ACTIVE` signing keys, refreshed by the readiness probe — alert on it reaching
  zero, watch it move across a rotation), and `iam.audit.entry` / `iam.audit.checkpoint`
  (see below). Standard JVM and HTTP-server binders are enabled too.
- **Tracing** — OpenTelemetry OTLP export (endpoint and sampler configurable via the
  usual `OTEL_*` environment variables).
- **Health** — SmallRye Health liveness/readiness on `/q/health[/live|/ready]`, with a
  degraded-subsystem registry so the server can start *degraded* rather than crash when
  a non-critical dependency is missing, and fail *closed* on a critical one (e.g.
  readiness is `DOWN` until an `ACTIVE` signing key exists).

### Tamper-evident audit log

Security-relevant events are recorded in a **per-tenant hash chain**: each entry hashes
over the previous entry's hash, so altering, inserting, deleting or reordering any entry
breaks the chain and is detected at the offending entry. Chains are strictly per-tenant —
one tenant can neither read nor affect another's chain.

Periodically the server produces a **signed checkpoint** over each chain's head. Because
the head hash transitively covers every prior entry, a single Ed25519 (EdDSA) signature
over it attests the whole chain up to that point: a holder of the public key can confirm
the log has not been truncated or rewritten behind the checkpoint, which an attacker
cannot forge without the private key. The bundled signer keeps an in-process key for
self-contained operation; a deployment can supply a KMS/HSM-backed signer without
touching the chain logic. Entries and checkpoints are published on an in-process
`iam.audit.*` event channel that a deployment observes to forward to a durable,
append-only sink (broker, object store, SIEM) — the chain core stays transport-agnostic.

The checkpoint interval is `iam.audit.checkpoint.interval` (a duration, default `1h`;
set `disabled` to turn the trigger off). Chain continuity and every form of tamper
detection are proven by unit tests.

The log can grow without bound, so verification is **constant-memory**: the chain math is
a pure per-entry fold step (`AuditChain.verifyNext`, mirroring the auth-flow reducer — no
I/O, no framework) and the storage is an outbound port (`TenantAuditLogRepository`) that
streams a tenant's entries as a reactive `Multi` ordered by sequence. Verification folds
the pure step over that stream and never materializes the whole chain, so it stays O(1) in
memory whatever the chain length; historical checkpoints are verified the same way, by
streaming to the anchored entry. The bundled in-memory repository is the self-contained
default; a deployment supplies a durable streaming adapter (e.g. reactive Postgres,
`ORDER BY sequence`) without touching the chain core.

## Benchmark — startup & footprint

A core goal is to be dramatically lighter than a traditional JEE-era server. Measured
on the assembled `tessera-server` (JDK 25, Quarkus 3.35.4) booting with the datasource
deactivated, so the figure isolates framework/application startup:

| Mode | Cold-start (to *started*) | Resident memory (RSS) |
|------|---------------------------|------------------------|
| **JVM** (`quarkus-run.jar`) | ~1.2–1.5 s | ~160–225 MiB |
| **Native** (GraalVM image) | *(target: sub-100 ms; not yet measured here — see note)* | *(target: tens of MiB)* |

For reference, Keycloak — a mature JVM OIDC server — typically takes several seconds to
start and holds hundreds of MiB resident; Tessera's JVM mode already starts in roughly a
second, and native-image is expected to bring cold-start into the tens-of-milliseconds
range with a fraction of the memory.

Build and measure the native executable with:

```bash
# Requires a GraalVM/Mandrel toolchain, or add -Dquarkus.native.container-build=true
# to build it inside a builder image (needs Docker/Podman).
mvn -Pnative -DskipITs -pl tessera-server -am package

# Cold-start + RSS of the produced executable:
/usr/bin/time -l ./tessera-server/target/*-runner
```

> The native numbers above are left as targets: the build host used for the current
> measurements has neither a GraalVM/Mandrel toolchain nor a container runtime available,
> so only JVM-mode figures are recorded. Re-run the command above on a host with the
> toolchain to fill them in.

## Roadmap

- [x] OAuth2 `/authorize` + `/token` Authorization Code flow with mandatory PKCE
      (S256) — single-use codes, RFC 9068 JWT access tokens, RFC 9207 `iss`
- [ ] Distributed (clustered) authorization-code store — the shipped store is
      single-node in-memory; a shared cache is needed for a multi-node deployment
- [ ] Remaining grants (client-credentials) and a registered-redirect-URI check
      at `/authorize`
- [ ] Dynamic client registration (RFC 7591)
- [ ] Refresh tokens & token introspection/revocation (RFC 7662 / 7009)
- [ ] Pluggable user/credential stores and a consent UI
- [ ] Propagate the tenant onto a future message-broker consumer path (the
      request-scoped resolver is shaped so a consumer interceptor can populate the
      same tenant context identically once messaging is introduced)
- [ ] Conformance against the OpenID Connect test suite
- [ ] Re-enable static analysis gates (Checkstyle / SpotBugs) in the build

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](./LICENSE). Tessera
bundles two small internal libraries; their provenance is recorded in
[`NOTICE`](./NOTICE).
