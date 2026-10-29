# Tessera

**A standalone, developer-friendly OIDC / OAuth 2.0 authorization server, built on
[Quarkus](https://quarkus.io) — a from-scratch alternative to Keycloak.**

Tessera issues and signs OpenID Connect / OAuth 2.0 tokens. The name is the Roman
*tessera* — a small token that proved a bearer's identity; fitting, for a service
whose whole job is issuing verifiable tokens of identity.

> **Status: early / experimental — but the token-issuance core is complete.** The
> cryptographic core (EdDSA signing-key lifecycle, JWKS, OIDC discovery), the reactive
> multi-tenant persistence layer (clients and rotating refresh-token families, each behind
> fail-closed row-level security), the functional auth-flow domain model, and the full
> confidential-client token-issuance vertical are in place:
>
> - **Authorization Code flow with mandatory PKCE (S256)** — `/authorize` → `/token`,
    >   issuing signed RFC 9068 JWT access tokens and OIDC ID tokens.
> - **Refresh-token grant** (`grant_type=refresh_token`) — single-use rotation with
    >   family reuse-detection (RFC 9700 §4.14).
> - **Client-credentials grant** (`grant_type=client_credentials`, RFC 6749 §4.4) — a
>   tenant-bound confidential client gets a token for itself, with its registered scopes,
>   audiences (narrowed by an RFC 8707 `resource` indicator) and roles.
> - **Token introspection** (RFC 7662, `/introspect`) and **token revocation**
    >   (RFC 7009, `/revoke`).
> - **Confidential + public client registry** — Argon2id client secrets, with an
    >   exact-match `redirect_uri` allow-list enforced before any code is issued.
>
> Remaining surfaces (a login/consent UI and interactive credential verification, dynamic
> client registration) are on the roadmap below. No
> known-open security gaps in the shipped vertical, but not yet recommended for production
> until the KMS-backed signing-key protection and multi-node stores land.

## What Tessera is — and is not

Tessera is a **multi-tenant OAuth 2.0 / OpenID Connect authorization core**, designed to be
embedded behind your own infrastructure rather than run as a turnkey identity product. Being
precise about that boundary matters.

**What it is**
- A production-shaped implementation of the confidential-client token-issuance vertical:
  **Authorization Code + PKCE (S256)** (`/authorize` → `/token`), the **refresh-token grant**
  with single-use rotation and family reuse-detection, the **client-credentials grant**,
  **token introspection** (RFC 7662)
  and **revocation** (RFC 7009) — issuing RFC 9068 JWT access tokens and OIDC ID tokens,
  with OIDC discovery + JWKS and EdDSA signing-key rotation.
- A **confidential + public client registry** — Argon2id-hashed client secrets on a dedicated
  worker pool, with an exact-match registered-`redirect_uri` allow-list enforced before a code
  is ever issued.
- **Multi-tenant and fail-closed** — per-tenant PostgreSQL row-level security, resolved at a
  single ingress chokepoint.
- **Hardened at the edge** — deny-by-default CORS, security headers, TLS redirect, ingress
  rate limiting, and a per-`(tenant, client)` credential brute-force throttle.
- **Operable** — Micrometer/Prometheus metrics, OpenTelemetry tracing, health probes, and a
  tamper-evident per-tenant audit log.

**What it is _not_ (yet)**
- **Not a full login _product_.** Tessera hosts one page of its own, the sign-in page at
  `/signin`: `/authorize` sends a browser that has no session there, so every client signs in
  on tessera's origin, whatever site it runs on. It takes a username and password and nothing
  more: no consent screen, second factor, sign-up or per-deployment theming yet. The
  `X-Subject-Id` header that an upstream authenticator
  once supplied instead is default-closed (`iam.subject.trust-header=false`): any inbound
  value is stripped, and a verified session cookie is the only way to establish a subject.
- **Not yet self-sufficient for production key protection.** Signing keys are wrapped with a
  development master key that is _refused_ outside dev/test; a KMS-backed wrapping adapter is
  required before a production deployment can boot.
- **Not yet a delegation server for AI agents.** Agents can authenticate as clients today
  (`client_credentials`, `private_key_jwt`, keyless workload identity), but an agent cannot yet
  act on a person's behalf with a delegated token. The design is written up and planned (Wave 4
  below): see [agentic IAM landscape](docs/research/agentic-iam-landscape-2026-10.md) and
  [agent delegation profile](docs/research/agent-delegation-profile.md).
- **Single-node for the ephemeral stores.** The refresh-token family store is durable
  (PostgreSQL, per-tenant RLS), but the authorization-code store and the rate limiter are
  in-process; a shared-cache backend for those is required before a multi-node deployment.

Releases use a `YY.MAJOR.MINOR` version scheme, one Greek-named release per named line; the
first tagged release will be `26.1.0 "Andromeda"`.

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
| `AuthorizeUseCase` | `GET /authorize` — validates an authorization request against the client's registered `redirect_uri` allow-list, starts the auth flow, returns a sealed `AuthorizeResult.Issued` or `AuthorizeResult.Failed`. |
| `TokenUseCase` | `POST /token` — redeems a single-use authorization code (PKCE verified), issues signed JWT access token + OIDC ID token + opaque refresh token. |
| `ClientCredentialsUseCase` | `POST /token` (`grant_type=client_credentials`) — authenticates a confidential client and issues an access token for the client itself: its registered scopes and audiences, its roles through the claim pipeline, its tenant in `realm_tenant`/`realm_baseline`; no refresh token. Revoking such a token at `/revoke` is accepted and does nothing: it introspects as active until it expires, so its lifetime is short (5 minutes by default, `iam.client-credentials.access-token-ttl`). |
| `RefreshUseCase` | `POST /token` (`grant_type=refresh_token`) — rotates a single-use refresh token, detects family reuse (RFC 9700 §4.14) and revokes the family on replay, re-issues the token set. |
| `IntrospectUseCase` | `POST /introspect` (RFC 7662) — grant-authenticated introspection of an access or refresh token. |
| `RevokeUseCase` | `POST /revoke` (RFC 7009) — grant-authenticated revocation of a token. |

#### Outbound ports (driven adapters)

These are the seams you implement when embedding Tessera in your own stack or when
replacing the bundled adapters:

| Port | Description |
|------|-------------|
| `AuthorizationCodeStorePort` | Store and consume authorization codes with **exactly-once** semantics — `store(code, grant)` / `consume(realm, code)`. Two adapters ship: a shared Infinispan cache with a per-entry TTL (the multi-node default) and an in-process concurrent map (the `@DefaultBean` fallback, used under the `test` profile and for single-node development). |
| `ClientRepositoryPort` | Load a registered client by realm and client ID — `findByClientId(realm, clientId)`. The bundled adapter is the reactive-Postgres `OAuthClientRepository`. |
| `ClientSecretVerifierPort` | Verify a presented client secret without exposing the stored hash — `verifySecret(realm, clientId, presentedSecret)`. The bundled adapter verifies Argon2id hashes on a dedicated worker pool. |
| `ClientKeySourcePort` | Resolve what a client's JWT assertions (RFC 7523) must match: the public keys and the expected `iss` and `sub` — `trustFor(realm, clientId)`. The bundled adapter reads a `private_key_jwt` client's registered JWK Set, or a workload-identity client's registered issuer and subject. |
| `ClientAssertionVerifierPort` | Verify a JWT client assertion against that trust: signature with an allowed asymmetric algorithm, `iss`, `sub`, `aud`, validity window and single-use `jti` — `verify(realm, trust, assertion)`. The bundled adapter uses Nimbus JOSE with a per-instance replay store. |
| `RefreshTokenStorePort` | Persist and rotate refresh-token families with reuse-detection. The bundled adapter is durable (reactive Postgres, per-tenant RLS). |
| `RefreshTokenTenantResolverPort` | Resolve the owning tenant for a presented refresh token so the request can bind its tenant context before touching tenant-scoped tables. |
| `AccessTokenIntrospectorPort` | Parse and validate a presented access token (signature, expiry, claims) for the introspection endpoint. |
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
| `signingkey.KeyRotationPolicy` | `KeyRotationPort` (scheduled rotation) |
| *(not yet modelled)* | `ClientRegistrationPort` (RFC 7591 dynamic registration) |

## Using Tessera

### As a running server

Tessera is a standard Quarkus application. The fastest path:

```bash
git clone https://github.com/meta-agentic/meta-iam.git
cd meta-iam

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
| `GET` · `POST /signin` | Hosted sign-in page, reached from `/authorize` when the browser has no session |
| `POST /token` | Token endpoint (authorization-code, `refresh_token` and `client_credentials` grants) |
| `POST /introspect` | Token introspection (RFC 7662) |
| `POST /revoke` | Token revocation (RFC 7009) |
| `GET /q/health` · `/q/health/ready` · `/q/health/live` | Health probes |
| `GET /q/metrics` | Prometheus metrics |

### As a standalone single-tenant origin

Tessera's tenant contract assumes a gateway in front that asserts `X-Tenant-Id`. A
deployment that has no such gateway — a container platform's own domain mapping, a bare
reverse proxy — runs it in **single-tenant mode** instead, which is the shape a first
deployment for one relying party usually takes. Why tessera is deployed on its own origin
rather than behind an application gateway, and what that costs, is recorded in
[docs/adr/ADR-IAM-002](docs/adr/ADR-IAM-002-standalone-public-origin.md).

| Setting | Effect |
|---------|--------|
| `TESSERA_FIXED_TENANT=<uuid>` | Every request binds this tenant at the zero baseline; the tenant/baseline headers are ignored, so a caller cannot pick another tenant. The readiness probe binds the same tenant. |
| `TESSERA_OIDC_ISSUER` and `IAM_KEYS_ISSUER` | Both set to the public origin, e.g. `https://iam.example.com`. |
| `IAM_KEYS_MASTER_KEY` | A real base64 256-bit master key from your secret manager; the development default is refused outside dev/test. |
| `TESSERA_BOOTSTRAP_ENABLED=true` + `TESSERA_BOOTSTRAP_CLIENT_ID/_SECRET/_REDIRECT_URIS`, `TESSERA_BOOTSTRAP_USER_USERNAME/_PASSWORD` | First boot provisions what is missing: an `ACTIVE` signing key for the tenant, one confidential client (`client_secret_basic`, `authorization_code` + `refresh_token`, `https` redirect URIs only), one password user. Idempotent; existing rows are never overwritten. |
| `TESSERA_CLIENT_CREDENTIALS_ENABLED=false`, `TESSERA_CLIENT_CREDENTIALS_ACCESS_TOKEN_TTL=PT5M` | Turn the `client_credentials` grant off (it then disappears from discovery too) or change its token lifetime. Which clients may use it, with which scopes, audiences (`aud` is never the issuer) and roles, is client registration data: the `allowed_grants`, `allowed_scopes`, `audiences` and `roles` columns of `oauth_client`. |
| `iam.client-assertion.trusted-issuers.<name>.issuer`, `.jwks-uri`, `.max-lifetime`, `.require-jti`, `.enforce-single-use` | Trust an external issuer for keyless (workload-identity) clients. A client is registered with `auth_method = 'WORKLOAD_IDENTITY'` and the `assertion_issuer` and `assertion_subject` its token must carry, unique across tenants. It calls `/token` with `client_credentials`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, its platform token as `client_assertion`, and its `client_id`, which is required (the token's `sub` names the workload, not the client); the token's audience must be tessera's issuer. The default `max-lifetime` of `PT5M` refuses common platform tokens, so set the issuer's own: for example `…trusted-issuers.google.issuer=https://accounts.google.com`, `…google.jwks-uri=https://www.googleapis.com/oauth2/v3/certs`, `…google.max-lifetime=PT1H`; and for a Kubernetes cluster (projected tokens live at least 10 minutes) `…trusted-issuers.cluster.issuer=<the cluster's service-account issuer>`, `…cluster.jwks-uri=<its public JWKS URL>`, `…cluster.max-lifetime=PT1H`. A platform token is exchanged again and again until the platform rotates it, so by default its `jti` (if any) is recorded and reuse is allowed until `exp`; `require-jti=true` refuses a token without one, and `enforce-single-use=true` (for an issuer that mints a token per request) accepts each `jti` once. `private_key_jwt` assertions always carry a `jti` and are used once. |
| `TESSERA_ARGON2_POOL_SIZE=4`, `TESSERA_ARGON2_MAX_WAITING=16`, `TESSERA_ARGON2_TENANT_SHARE=0.5`, `TESSERA_ARGON2_WAIT_DEADLINE=PT1S` | Bound the cost of credential verification. Every client authentication costs one Argon2id pass, also for an unknown `client_id`. At most `pool-size + max-waiting` verifications are admitted at once, one tenant may hold `tenant-share` of them (so `ceil(1 / tenant-share)` tenants flooding at once fill the cap), and one still waiting after `wait-deadline` is dropped. A refused request gets `503` with `Retry-After`. With a gateway-asserted `X-Tenant-Id`, the per-tenant share is only as strong as the edge's stripping of a client-supplied header. The defaults are provisional until a perf run measures them. |
| `TESSERA_REQUIRE_SENDER_CONSTRAINT=false` | Lets a secret-authenticated confidential client that can present no client certificate (a back-end-for-frontend behind a TLS-terminating edge) receive a plain Bearer token. Leave at the default `true` wherever clients can do mTLS or DPoP. |
| `TESSERA_CORS_ORIGINS=https://app.example.com` | Allows a relying party that collects the credential on its own page to `POST /login` cross-origin with credentials. The hosted sign-in page posts to its own origin and needs nothing listed. `/authorize` never answers cross-origin, whatever is listed (RFC 9700 §2.6). |
| `TESSERA_SIGN_IN_TTL=PT10M` (`iam.authflow.sign-in-ttl`) | How long an authorization request may wait on the sign-in page. |
| build with `-Dquarkus.profile=prod,singlenode` | For a deployment that runs exactly one instance: the in-process authorization-code and sign-in stores are used and no Infinispan server is needed. Run more than one instance and codes minted on one node cannot be redeemed on another, nor a sign-in started on one finished on another — use the default profile and a shared cache instead. |

The ID token then carries `realm_tenant` and `realm_baseline` when the `profile` scope is
granted, which is how a relying party that scopes its own data by tenant learns which tenant
a signed-in user belongs to without guessing.

A relying party sends the browser to `/authorize` and needs no login page of its own. When the
browser has no `tessera_session`, the client and redirect URI are validated and the request is
parked: `303` to `/signin?txn=…`, with a `tessera_authz` cookie (`HttpOnly`, `Secure`,
`SameSite=Lax`, path `/signin`) that binds it to that browser. The page posts to its own origin
with a synchronizer token; on success it sets the session cookie and answers the parked request
with `303` to the registered redirect URI carrying `code`, `state` and `iss`. A post from
another site (`Sec-Fetch-Site`), without the binding cookie or token, or after the request was
answered, is refused before the password is checked. The page carries its own
Content-Security-Policy, which lets its form post to tessera and end at the client's origin; the
server-wide one skips that path. `POST /login` stays for a relying party that collects the
credential itself.

### As a library dependency

`tessera-api` is the stable hexagonal contract — domain types, port interfaces, and
the application service. Depend on it to build a custom adapter or to embed Tessera's
core logic into your own Quarkus application:

```xml
<dependency>
  <groupId>ai.meta-agentic</groupId>
  <artifactId>tessera-api</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

The full artifact list published to Maven Central:

| Artifact | Use |
|----------|-----|
| `ai.meta-agentic:tessera-domain` | Domain types only (no Quarkus dependency) |
| `ai.meta-agentic:tessera-api` | Port interfaces + application service |
| `ai.meta-agentic:tessera-persistence` | Bundled Hibernate Reactive / Postgres adapter |
| `ai.meta-agentic:tessera-rest` | Bundled JAX-RS adapter |
| `ai.meta-agentic:tessera-statemachine` | Auth-flow state-machine library |
| `ai.meta-agentic:tessera-observability` | Metrics / tracing / health module |

> Snapshots are not yet published. The first tagged release, `26.1.0 "Andromeda"`, is
> gated on the `tessera-e2e` integration suite passing an end-to-end OIDC flow against a
> real client service.

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

### Wave 1 — machine-facing token issuance (accumulating toward `26.1.0 "Andromeda"`, gated on the e2e suite)
- [x] OAuth 2.0 Authorization Code flow with mandatory PKCE (S256)
- [x] RFC 9068 JWT access tokens, OIDC ID tokens
- [x] Refresh-token grant — single-use rotation with family reuse-detection (RFC 9700 §4.14)
- [x] `client_credentials` grant (RFC 6749 §4.4) — tenant-bound confidential clients, registered scopes, audiences and roles
- [x] JWT client assertions (RFC 7523) on `client_credentials`: `private_key_jwt` with a registered JWK Set, and keyless workload identity — a token from a trusted external issuer (a cloud platform, Kubernetes, SPIFFE) whose key set is fetched over https, with a per-issuer maximum lifetime and `jti` rules (`iam.client-assertion.trusted-issuers.*`)
- [x] Token introspection — RFC 7662 (`POST /introspect`)
- [x] Token revocation — RFC 7009 (`POST /revoke`)
- [x] Confidential (Argon2id) + public (PKCE) client registry with `redirect_uri` allow-list
- [x] EdDSA (Ed25519) signing keys with `PENDING → ACTIVE → RETIRING → RETIRED` lifecycle
- [x] OIDC discovery (`/.well-known/openid-configuration`) + JWKS endpoint
- [x] Multi-tenant PostgreSQL adapter with fail-closed row-level security
- [x] Shared-cache (Infinispan) authorization-code store — a code minted at `/authorize` on one node is redeemable at `/token` on another
- [x] Edge hardening: deny-by-default CORS, security headers, TLS redirect, ingress rate limiting, credential-verification throttle
- [x] Tamper-evident per-tenant audit log with signed checkpoints
- [x] First-class observability: Micrometer, OpenTelemetry, SmallRye Health

### Wave 2 — interactive login
- [ ] Subject repository port + pluggable credential verifier (password, TOTP, WebAuthn)
- [x] Hosted sign-in page (server-side rendered, password only) — `/authorize` → `/signin` → code, bound to the browser, shared across nodes
- [ ] Consent UI, and per-deployment theming of the sign-in page

### Wave 3 — RFC completeness & operations
- [ ] Dynamic client registration — RFC 7591
- [ ] Key rotation port (scheduled, driven by `KeyRotationPolicy`)
- [ ] Realm management API

### Wave 4 — agents acting on a person's behalf
Planned, following the [agent delegation profile](docs/research/agent-delegation-profile.md); the
standards behind it are rated in the [agentic IAM landscape](docs/research/agentic-iam-landscape-2026-10.md).
- [ ] Decision record for the token exchange grant and the delegation profile (token exchange is
  excluded at compile time today, on purpose, until that record is accepted)
- [ ] Per-resource audience at `/authorize` — an RFC 8707 `resource` indicator, so `aud` names the
  API a token is for (also required by the MCP authorization specification)
- [ ] Token exchange grant — RFC 8693, single hop: the acting agent is identified by its own client
  authentication (mTLS or `private_key_jwt`), never by a separate actor token; the token names the
  person (`sub`) and the agent (`act`); scope and audience only narrow, expiry never extends, no
  refresh token
- [ ] Delegated tokens from the authorization-code flow, with standing delegation grants (resources,
  scopes, sub-agents, depth, expiry) and per-task approval for sensitive scopes (RFC 9396)
- [ ] Sub-agent hand-off — a single-use token the sub-agent exchanges for its own; depth cap (default
  2, at most 4) and no cycles
- [ ] Delegation lineage and cascading revocation — revoking one link, or withdrawing a grant,
  deactivates every token derived from it; introspection reports the chain
- [ ] Proof-of-possession for confidential clients — DPoP on `client_credentials` and token exchange,
  so every delegated token is bound to its presenter
- [ ] Validation guide and signed test vectors for resource servers (an MCP gateway or any API)

### Ongoing
- [ ] Distributed rate limiting (the shipped ingress limiter and credential-verification throttle are single-node in-memory; a shared-cache backend enforces limits fleet-wide)
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
