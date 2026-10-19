# ADR-IAM-003 — Tenant tier source of truth, and a path-scoped issuer alongside header-only tenant resolution

| Field | Value |
|---|---|
| Status | **Accepted**, with one open item (see [Open items](#open-items)) |
| Date | 2026-09-23 |
| Ratified | 2026-10-19 |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (standalone public origin), [ADR-IAM-001](ADR-IAM-001-audit-checkpoint-key-custody.md) (key custody) |

---

## Background

Tessera can serve many tenants from one server. Today only one thing keeps tenants apart when a token is introspected: each tenant has its own signing keys. Access tokens do not name their tenant, and introspection never checks `iss`. If two tenants shared keys, a token minted for one would introspect as `active` in the other.

Two questions follow. Where does a tenant's tier (Starter, Pro, Enterprise) live? And how does a tenant get its own issuer URL (`…/realms/<id>`) without letting the URL path choose the tenant, which ADR-IAM-002 forbids?

Facts the decisions rest on:
- Tenants have no registry and no name. `TenantId` wraps a UUID, and nothing records a tenant's tier or status.
- `signing_key` is tenant-scoped under `FORCE ROW LEVEL SECURITY` and holds the private material. Sharing a key set would need either a cross-tenant readable row or the same private key copied once per tenant.
- `sub` is unique only per `(tenant, baseline)`. With one shared `iss`, the pair `(iss, sub)` does not identify one user (OIDC Core §2).
- `signing_key` already has an `issuer` column, stamped at mint time and read by no query. `IssuerConsistencyCheck` compares two configured scalars at startup.
- Two classes already read outside row security through the raw `Mutiny.SessionFactory`: `DbRefreshTokenTenantResolver` and `FirstBootProvisioner`. `TenantChokepointArchTest` watches only the `repository` package, so it does not see them.
- The runtime database role `iam_app` gets write access to every new table by default.
- Tessera has no messaging layer.

## D1 — A tenant registry is the source of truth for tier and status

**Decision.** A `tenant` table holds the tenant, its tier, its status, and the opaque realm id the server mints for each of its realms. It sits outside per-tenant row security, because it must be read before the server knows which tenant a request belongs to. Tier is per tenant and covers all its baselines.

**Consequences.**
1. A tenant missing from the registry gets no token. It is not defaulted to Starter.
2. Suspension bites immediately: the tenant's tokens introspect as inactive and its refreshes fail. A registry read error is a `503`, never a default. Any cache on the registry sets the longest a suspension can take to apply, and its TTL is configured.
3. Only a separate administrative database role can write the table. The migration revokes `INSERT`, `UPDATE` and `DELETE` from `iam_app`, and an integration test proves it. A request-path bug cannot change a tier.
4. The registry is read through one narrow port that returns only tenant, tier, status and realm ids, never joined to tenant data.
5. A build rule names every class allowed to bypass row security. `TenantChokepointArchTest` covers the whole persistence layer, with an allowlist of `DbRefreshTokenTenantResolver`, `FirstBootProvisioner` and the registry adapter. Raw-factory users outside persistence, such as `SigningKeyReadinessCheck`, get a rule of their own.
6. Upgrading needs a migration that registers existing tenants, the fixed tenant and the development seed, or everyone is refused.
7. A tier change is a write to this table, so no messaging system is needed. Reacting to tier changes that start outside tessera is out of scope.

## D2 — The path must agree; it never chooses

**Decision.** If a request path names a realm, it must match the tenant from the header or the fixed tenant, or `TenantResolutionFilter` refuses the request with `400`.

**What it means.** This guards against misrouting. It is not the isolation mechanism; that rests on per-realm client credentials and key sets (D4).

**Consequences.**
1. In fixed-tenant mode, the path realm must equal the fixed tenant.
2. The realm is read from the matched route parameter, never by parsing the raw path. Encoded `/`, dot segments, matrix parameters and case variants are refused. The forwarded-prefix setting stays off.
3. A deployment whose edge maps the path to the header gains nothing from D2 and must say so.

## D3 — A per-tenant `iss` for every multi-tenant deployment

**Decision.** The issuer is `base` in single-tenant mode and `base/realms/<opaque id>` otherwise. `base` is `iam.oidc.issuer`, which stays server configuration and is never taken from the request. The id is minted by the server, never chosen by a customer, and never reused.

**What it means.** Without it, two tenants' users could share the same `(iss, sub)`, and a relying party could merge them.

**Consequences.**
1. The per-tenant issuer is a requirement of multi-tenancy, not a tier feature.
2. Each tenant gets its own discovery document and key set (D5).
3. Switching an existing deployment changes its `iss`, and every relying party must be told (see the open item).
4. On first boot, one stored row binds the base issuer to its tenant. Startup refuses a mode that would reuse it for another tenant.
5. Going from multi-tenant to single-tenant, or restoring without the database, needs a new base URL.
6. `IssuerConsistencyCheck` compares the configured bases rather than two scalars. The key row's `issuer` is filled with the derived issuer at mint time and backfilled for existing keys.
7. `DiscoveryEndpointTest.issuerIsConfiguredNotHost` keeps its base case. Two cases are added: a spoofed `Host` with a matching realm path still gets the configured base, and a spoofed `Host` with a mismatched realm path is refused (D2).
8. The issuer is the publicly reachable identifier. An in-cluster caller resolves that name, for example through split-horizon DNS, rather than fetching from an internal URL. A proxy must keep the realm path byte for byte.

**Why one row and not a ledger.** The dangerous cases are rare operator mode switches. A one-row binding plus a startup check blocks them without a ledger of retire and reactivate rules.

## D4 — No shared signing keys, and a second check in the token layer

**Decision.** (a) Tenants never share key material, in any tier. (b) Access tokens carry their tenant and baseline, and introspection refuses a token whose realm or `iss` does not match the realm it is presented in.

**What it means.** Rollout is in two phases: emit the claims, wait one token lifetime, then enforce. Tokens without the claims are inactive.

**Consequences.**
1. Two independent tenant boundaries instead of one.
2. D4b depends on nothing else here and goes first, followed by D1, then D2, D3 and D5.
3. The comparison lives in `IntrospectService`, so no adapter can drop it. It covers the full realm, `(tenant, baseline)`: today a token minted for one baseline introspects as active in another baseline of the same tenant.
4. Both mint paths, the token service and the refresh service, emit the claims, after every claim contributor and under names a contributor cannot set.
5. Comparing `iss` separates tenants only once D3 ships.
6. One key set per tenant multiplies the KMS keys under ADR-IAM-001.

## D5 — Per-tenant discovery and key sets, global timings

**Decision.** Each tenant has its own discovery and JWKS routes. The cache TTL and the key dwell stay global, so one startup check enforces TTL < dwell. A promoted key waits out the dwell before it signs, except at first boot. The base key set serves only the base realm.

**Consequences.**
1. Relying parties that hard-coded the base JWKS for another realm must move to that realm's URL.
2. Known defect: in header mode, discovery and JWKS are publicly cacheable on a shared URL without `Vary: X-Tenant-Id`, so a shared cache can serve one tenant's keys to another. The fix is `Vary`, or per-tenant URLs.

## Rejected alternatives

- **Tier in static configuration.** A second tenant list that drifts, with no place for lifecycle.
- **Tier in a gateway-asserted header.** Makes privileges a request input, and the shipped topology has no gateway.
- **The path as the tenant source.** Reverses ADR-IAM-002 and lets the caller choose the tenant.
- **A decorative, unchecked path.** The server would advertise realm scoping it does not enforce.
- **A shared Starter key set with a compensating claim.** Trades a cryptographic boundary for a check one deleted line removes.
- **Customer-chosen slugs.** Squatting, lookalikes, and reuse after deletion inside a value relying parties pin.
- **An append-only issuer ledger.** More machinery than the rare mode switches need.
- **Per-tenant subdomain issuers.** Multiplies DNS, certificates and internal addressing by the number of tenants.

## Open items

- **Upgrade path for an existing deployment whose issuer changes shape.** This covers how `signing_key.issuer` is backfilled and how relying parties are told.
