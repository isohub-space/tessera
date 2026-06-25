# Tessera

**A standalone, developer-friendly OIDC / OAuth 2.0 authorization server, built on
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

### Application ports

The hexagonal boundary is expressed as Java interfaces in `tessera-api`. All
extension points — from persistence to signing to claim enrichment — are driven
ports (outbound) that you can replace without touching the domain.

#### Inbound ports (use cases)

These are the application's entry points, implemented by the application service and
called by the REST adapter:

| Port | Description |
|------|-------------|
| `AuthorizeUseCase` | `GET /authorize` — validates an authorization request, starts the auth flow, returns a sealed `AuthorizeResult.Issued` or `AuthorizeResult.Failed`. |
| `TokenUseCase` | `POST /token` — redeems a single-use authorization code (PKCE verified), issues signed JWT access token + OIDC ID token + opaque refresh token. |

#### Outbound ports (driven adapters)

These are the seams you implement when embedding Tessera in your own stack or when
replacing the bundled adapters:

| Port | Description |
|------|-------------|
| `AuthorizationCodeStorePort` | Store and consume authorization codes with **exactly-once** semantics — `store(code, grant)` / `consume(realm, code)`. The bundled adapter is an in-process concurrent map (single-node only; a shared-cache adapter is on the roadmap). |
| `ClientRepositoryPort` | Load a registered client by realm and client ID — `findByClientId(realm, clientId)`. |
| `ClientSecretVerifierPort` | Verify a presented client secret without exposing the stored hash — `verifySecret(realm, clientId, presentedSecret)`. |
| `KeyProviderPort` | Three operations: `sign(realm, keyId, signingInput)` (EdDSA), `publishedJwks(realm)` (public JWKS), `currentSigningKey(realm)` (the `ACTIVE` key for this realm). |
| `TokenSignerPort` | Produces a compact JWT string from a claim set — `sign(realm, typ, claims)`. Implemented by the bundled EdDSA signer; swap for a KMS-backed signer without touching the domain. |
| `ClaimSourcePort` | Enriches a token with deployment-specific claims — `loadClaimContext(subject, realm, scopes)`. Implement this to add roles, groups, or any custom assertion from your user store. |
| `OpaqueIdentifierPort` | Generates opaque identifiers — `newAuthorizationCode()` and `newTokenId()`. The bundled implementation uses `SecureRandom`; a deployment can use a distributed ID scheme instead. |

#### Domain richness ahead of ports (future waves)

The domain already models these concepts; the adapters will follow in later waves:

| Domain concept | Coming port |
|----------------|-------------|
| `credential.*` (PasswordHash, TotpSecret, WebAuthnAuthenticator) | `CredentialVerifierPort` |
| `authflow.*` (AuthExchange, ChallengeDescriptor, MfaKind) | `SubjectRepositoryPort` + interactive login flow |
| `client.grant.ClientCredentials` | `ClientCredentialsUseCase` (inbound) |
| `token.RefreshToken` | `RefreshTokenStorePort` |
| `signingkey.KeyRotationPolicy` | `KeyRotationPort` |
| *(not yet modelled)* | `TokenRevocationPort` (RFC 7009), `TokenIntrospectionPort` (RFC 7662), `ClientRegistrationPort` (RFC 7591) |

## Using Tessera

### As a running server

Tessera is a standard Quarkus application. The fastest path:

```bash
git clone https://github.com/isohub-space/tessera.git
cd tessera

# Build (unit tests only; integration tests need Docker — see below).
mvn -DskipITs verify

# Run in dev mode (live reload) from the composition root.
mvn -pl tessera-server quarkus:dev
```

The server listens on `http://localhost:8090` by default. Key endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | JSON Web Key Set (public signing keys) |
| `GET /authorize` | Authorization Code + PKCE endpoint |
| `POST /token` | Token endpoint |
| `GET /q/health` · `/q/health/ready` · `/q/health/live` | Health probes |
| `GET /q/metrics` | Prometheus metrics |

### As a library dependency

`tessera-api` is the stable hexagonal contract — domain types, port interfaces, and
the application service. Depend on it to build a custom adapter or to embed Tessera's
core logic into your own Quarkus application:

```xml
<dependency>
  <groupId>space.isohub</groupId>
  <artifactId>tessera-api</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

The full artifact list published to Maven Central:

| Artifact | Use |
|----------|-----|
| `space.isohub:tessera-domain` | Domain types only (no Quarkus dependency) |
| `space.isohub:tessera-api` | Port interfaces + application service |
| `space.isohub:tessera-persistence` | Bundled Hibernate Reactive / Postgres adapter |
| `space.isohub:tessera-rest` | Bundled JAX-RS adapter |
| `space.isohub:tessera-statemachine` | Auth-flow state-machine library |
| `space.isohub:tessera-observability` | Metrics / tracing / health module |

> Snapshots are not yet published. The first release (`0.1.0`) is gated on the
> `tessera-e2e` integration suite passing an end-to-end OIDC flow against a real
> client service.

### Extending Tessera

The most common extension point is `ClaimSourcePort` — implement it to enrich tokens
with your application's roles, groups, or custom claims:

```java
@ApplicationScoped
public class MyClaimSource implements ClaimSourcePort {

    @Override
    public Uni<ClaimContext> loadClaimContext(String subject, String realm, Set<String> scopes) {
        // Load roles from your user store and return them as a ClaimContext.
        return myUserService.findRoles(subject)
            .map(roles -> ClaimContext.of(Map.of("roles", roles)));
    }
}
```

Tessera picks up your implementation via CDI — no configuration required. The same
pattern applies to every other outbound port: declare a `@ApplicationScoped` bean
that implements the port interface, and it replaces the bundled default.

To replace the persistence adapter entirely, implement `ClientRepositoryPort`,
`AuthorizationCodeStorePort`, and `KeyProviderPort` against your preferred store
(Redis, MongoDB, a cloud key-management service) and exclude the bundled
`tessera-persistence` module from your composition root.

## Integration tests

The `*IT` suites (row-level-security isolation, JWKS endpoint) boot against a real
PostgreSQL via [Testcontainers](https://testcontainers.org), so they require a
running Docker daemon. They run in the `verify` phase; pass `-DskipITs` to skip
them when Docker isn't available.

```bash
# Full build including integration tests (requires Docker).
mvn verify

# Unit tests only (no Docker needed).
mvn -DskipITs verify
```

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
on the assembled `tessera-server` (JDK 25, Quarkus 3.37.0) booting with the datasource
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

Tessera evolves in waves. Each wave is releasable on its own; a new minor version is
tagged when the wave's integration test suite passes an end-to-end OIDC flow.

### Wave 1 — shipped (v0.1.0, gated on e2e suite)
- [x] OAuth 2.0 Authorization Code flow with mandatory PKCE (S256)
- [x] RFC 9068 JWT access tokens, OIDC ID tokens
- [x] EdDSA (Ed25519) signing keys with `PENDING → ACTIVE → RETIRING → RETIRED` lifecycle
- [x] OIDC discovery (`/.well-known/openid-configuration`) + JWKS endpoint
- [x] Multi-tenant PostgreSQL adapter with fail-closed row-level security
- [x] Tamper-evident per-tenant audit log with signed checkpoints
- [x] First-class observability: Micrometer, OpenTelemetry, SmallRye Health

### Wave 2 — interactive login
- [ ] Subject repository port + pluggable credential verifier (password, TOTP, WebAuthn)
- [ ] Login and consent UI (server-side rendered; replaceable)
- [ ] Refresh token store port + token rotation
- [ ] `client_credentials` grant (machine-to-machine)

### Wave 3 — RFC completeness
- [ ] Token introspection — RFC 7662 (`POST /introspect`)
- [ ] Token revocation — RFC 7009 (`POST /revoke`)
- [ ] Dynamic client registration — RFC 7591
- [ ] Key rotation port (scheduled, driven by `KeyRotationPolicy`)
- [ ] Realm management API

### Ongoing
- [ ] Distributed authorization-code store (the shipped store is single-node in-memory; a shared-cache adapter is needed for multi-node)
- [ ] Native-image build measurements and CI publication
- [ ] OpenID Connect conformance test suite
- [ ] Static analysis gates (Checkstyle / SpotBugs) re-enabled in build

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) and
[`SECURITY.md`](./SECURITY.md) before opening a pull request. By contributing you
agree to the project's [CLA](./CLA.md).

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](./LICENSE). Tessera
bundles two small internal libraries; their provenance is recorded in
[`NOTICE`](./NOTICE).
