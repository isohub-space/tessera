# ADR-IAM-003 — Tenant tier source of truth, and a path-scoped issuer alongside header-only tenant resolution

| Field | Value |
|---|---|
| Status | **Proposed** — awaiting ratification. Not a decision until accepted. |
| Date | 2026-09-23 |
| Amended | 2026-09-29: security review. D1, D2, D3, D4b and D5 are tightened, the threat model is extended, and two statements about the existing code are corrected. Each amendment is marked **Amendment** in place. |
| Spike | tenant tier as source of truth + path-scoped issuer vs header-only tenant resolution (time-box 3 days, deliverable = this record) |
| Affects | tenant resolution, issuer configuration, signing-key topology, introspection, discovery/JWKS |
| Relates to | [ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) (standalone public origin), [ADR-001](ADR-001-audit-checkpoint-key-custody.md) (key custody) |

---

## Context

The spike posed two questions it described as entangled but separate:

1. Where does a tenant's tier live, given that there is no tenant registry?
2. How does an Enterprise path-scoped issuer (`/realms/{tenant}`) coexist with the
   header-only, fail-closed tenant resolution without weakening it?

Reading the code changed the shape of both. Five findings are stated first, because three of
them contradict premises the spike was written on and one of them inverts the answer the
spike expected.

### Finding 1 — access tokens carry no tenant claim, so the keyset is the *only* tenant boundary

The spike says a Starter token's tenant "is carried only by the `tenant_id` claim". **There is
no `tenant_id` claim.** `IssuedTokenClaims.accessToken` assembles exactly:

```java
claims.put("iss", issuer);
claims.put("sub", subjectId);
claims.put("aud", …);
claims.put("client_id", clientId);
claims.put("iat", issuedAt.getEpochSecond());
claims.put("exp", expiresAt.getEpochSecond());
claims.put("jti", jti);
claims.put("scope", String.join(" ", scopes));
```

plus `cnf` on the sender-constrained overload. Nothing names the tenant.

`JwsAccessTokenIntrospector.verify(realm, token)` does not close the gap. It checks
`alg=EdDSA`, `typ=at+jwt`, a present `kid`, then selects a key from
`keyProvider.publishedJwks(realm)` and verifies the signature. **It never reads `iss`, and
the claims it returns (`VerifiedAccessToken`) do not include one.** Its own javadoc states
the property it depends on:

> Only keys returned by `KeyProviderPort#publishedJwks` for `realm` are trusted — a token
> signed by another tenant's key is not published here and so does not verify, **which is
> the cryptographic tenant boundary**.

`IntrospectResource` takes that realm from `tenantContext.realm()` — the header-resolved or
fixed tenant — and passes it straight through.

**Consequence, and it is the central one: the keyset partition is not *a* tenant boundary on
the introspection path, it is the *whole* boundary.** If two tenants share a keyset, a token
minted for tenant A verifies under tenant B's realm and introspection returns `active` with
A's `sub`, `client_id` and `scope` presented as B's. That is not a degraded boundary. It is
tenant confusion with no remaining check to catch it.

The spike asked whether a shared Starter keyset is "acceptable, and what compensates". On the
code as it stands, nothing compensates, because there is nothing else looking.

### Finding 2 — a shared keyset is not cleanly representable anyway

`signing_key` is tenant-scoped and under `FORCE ROW LEVEL SECURITY` (V1), and V2 adds the
private material to that same table, explicitly inheriting the policy: private material is
readable only by a transaction bound to the owning tenant, and the schema fails closed when
no `app.tenant_id` is set. Key selection is by tenant:

```sql
CREATE INDEX idx_signing_key_selection ON signing_key (tenant_id, issuer, key_use, state);
```

So "Starter shares one keyset" has only two implementations. Either a cross-tenant readable
key row — an RLS bypass, which is precisely what `TenantChokepointArchTest` and the RLS
isolation ITs exist to forbid — or the *same private key material duplicated into one row per
tenant*, which is cryptographically identical to sharing while multiplying the number of
places the private key is stored. The clean form is forbidden; the achievable form is
strictly worse than either alternative.

### Finding 3 — a path realm needs the registry, so the two questions are not independent

`TenantId` wraps a UUID, and `TenantHeaders.parse` requires `UUID.fromString`. A tenant has no
name. An issuer of `https://iam.example.com/realms/{uuid}` is legal and useless; the reason an
adopter wants a path realm is that it reads `/realms/acme`.

Turning a path segment into a `TenantId` therefore requires a stable slug-to-tenant mapping —
which *is* the tenant registry of question 1. **The path-scoped issuer depends on the tier
source of truth.** They are not two decisions to be taken together for convenience; one is a
prerequisite of the other, and the ordering constrains delivery.

### Finding 4 — per-realm issuers are already representable in persistence

`signing_key` carries an `issuer` column, which the key-rotation service stamps at mint time and
V2 indexes, although no query reads it yet (see D3). `OidcDiscoveryConfig.issuer()` already
documents the intent:

> The `issuer` is server configuration, **resolved per realm** […] For the baseline tier a
> single configured issuer serves every realm; per-realm / per-tenant issuers are a later tier.

What actually assumes one global issuer is the configuration surface and
`IssuerConsistencyCheck`, which at startup compares two scalars character-for-character:

```java
if (!java.util.Objects.equals(oidcIssuer, keysIssuer)) { … }
```

That check is correct and worth keeping, but a scalar equality cannot express "these two
derive the same per-realm value". This is the concrete obstacle, and it is smaller than the
spike assumed: it is a config and startup-check problem, not a schema one.

### Finding 5 — this ground is already covered by an accepted decision

[ADR-IAM-002](ADR-IAM-002-standalone-public-origin.md) rejected **"deriving the tenant from
the request host or path"** — "it moves a security-load-bearing decision into string handling
over a value the caller controls". This ADR does not reverse that, and must not be read as
doing so. The decisions below keep the path strictly non-authoritative.

---

## Decisions

### D1 — Tier source of truth: a tenant registry table, outside per-tenant RLS, written administratively; unknown tenant is refused

A new `tenant` registry table is the source of truth for `(tenant, slug, tier, status)`. It is **inherently cross-tenant**: the registry must be readable *before* a request is scoped to a tenant, because reading it is part of establishing which tenant that is. It therefore cannot sit under the `app.tenant_id` RLS policy that protects every other tenant-scoped table.

**Amendment: it is not the first root outside RLS.** V6 already created `refresh_family_directory` without RLS, and `DbRefreshTokenTenantResolver` (`adapter.persistence.refresh`) reads it through the raw `Mutiny.SessionFactory`. `FirstBootProvisioner` (`adapter.persistence.bootstrap`) does the same. Neither class is in the package the arch rule watches, so the package-placement hole described below already exists. The registry is the second such root, and the bounds below apply to both.

That exemption is the dangerous part, so it is bounded explicitly:

- The registry is reached through a **single narrow port** returning only
  `(tenant, tier, status)` — never through `TenantScopedSession`, and never joined to
  tenant-scoped data.
- **The registry repository stays inside the package the arch rule watches, with an
  enumerated exemption.** This needs stating precisely, because the obvious implementation
  is the unsafe one. `TenantChokepointArchTest.repositories_routeThrough_tenantScopedSession`
  is scoped by package: *no class in* `…adapter.persistence.repository..` *may depend on*
  `Mutiny$SessionFactory`. A registry read must not be tenant-scoped — that is the whole
  point of it — so it cannot go through `TenantScopedSession` and must reach the raw session
  factory, which that rule forbids. There are exactly two ways to satisfy the build, and they
  are not equivalent:

  1. put the registry repository *outside* `…repository..`, whereupon the rule stops seeing
     it and the build goes green because the guard was moved, not satisfied; or
  2. keep it inside the package and add an explicit, by-name exclusion to the rule.

  **Take (2).** Option (1) is indistinguishable from (2) in CI and opposite in meaning, and it
  leaves the next cross-tenant repository free to be added the same way with nothing to
  notice. An exemption the test enumerates is a decision someone has to edit the test to
  make; an exemption obtained by package placement is a hole no test can report.
- **Amendment: the rule covers the whole persistence layer.** An enumerated exemption only means something if the rule sees every class that could need one. `TenantChokepointArchTest` is rewritten over `dev.tessera.iam.adapter.persistence..`: only `TenantScopedSession` and an enumerated allowlist may depend on `Mutiny$SessionFactory`. The allowlist starts as `DbRefreshTokenTenantResolver`, `FirstBootProvisioner` and the registry adapter. Raw-factory users outside that module, today `SigningKeyReadinessCheck` in the launcher, are enumerated in a rule of their own so they are not left unwatched.
- **Amendment: writes are administrative only, and the database enforces it.** V1 gives `iam_app` `SELECT, INSERT, UPDATE, DELETE` on every future table through `ALTER DEFAULT PRIVILEGES`, so a registry table without RLS would be writable from the request path by default. The registry migration revokes `INSERT, UPDATE, DELETE` on `tenant` from `iam_app`, and administrative writes use a separate role. An integration test shows that `iam_app` cannot write the table. A request-path bug must not be able to change a tenant's tier, status or slug.
- **Amendment: lifecycle and error paths.** A suspended tenant's existing access tokens introspect as `inactive`, and its refresh families fail to refresh; suspension does not only block issuance. A registry read error is a `503`, never a fallback to a default tier or status. If the registry is cached, the cache TTL is the longest a suspension can take to bite, and it is stated in configuration.

**Fail-closed rule: a tenant absent from the registry gets no tier and no token.** It is not
defaulted to Starter. Two reasons: an unknown tenant is an unknown principal, not a tier
question; and defaulting an unknown tenant into the baseline tier is defaulting it into
whatever the weakest tier's isolation happens to be, which is exactly the failure this ADR
exists to prevent.

**Rejected alternatives.**

- **A1a — static server configuration keyed by tenant.** Rejected. A tier change needs a
  restart or a config reload; the map is a second tenant list that can silently disagree with
  the data; there is nowhere to record lifecycle (created, suspended, deleted); and it does
  not solve Finding 3, because a config map is not a place a slug reservation can be enforced
  for uniqueness.
- **A1b — a tier claim asserted by the gateway alongside the tenant header.** Rejected. It
  makes the tier a request-time input, so an edge misconfiguration promotes a tenant's
  privileges. Worse, it does not exist in the deployment shape that actually ships: under
  ADR-IAM-002 there is no gateway, and in fixed-tenant mode `TenantResolutionFilter` ignores
  the ingress headers entirely. A channel that is absent in the primary topology cannot be
  the source of truth for it.
- **A1c — derive the tier from what the tenant already has, e.g. whether it owns a keyset.**
  Rejected as circular: the keyset topology is the thing the tier is meant to decide.

### D2 — The two-channel rule: the header (or fixed tenant) is the sole source; a path realm is a constraint that must agree

Stated as an invariant a test can pin:

> **For every tenant-scoped request, if the request path carries a realm segment, the tenant
> that segment resolves to MUST equal the tenant already bound from the header or the fixed
> tenant. If it does not, or if the segment does not resolve, the request is rejected with a
> `400` before any resource is reached. The path never supplies a tenant the header did not.**

**Where the check lives: inside `TenantResolutionFilter`.** It already runs at
`Priorities.AUTHENTICATION`, is already bound by `@TenantScoped`, and already holds the
`ContainerRequestContext` the path is read from. Putting the comparison anywhere else makes it
a thing each resource must remember to do, which is the property the chokepoint exists to
remove. Path `/realms/acme` with a header naming another tenant is rejected there, fail-closed,
exactly as a missing tenant header is today.

In fixed-tenant mode the rule degenerates usefully rather than lapsing: the path realm must
equal the configured fixed tenant, so a caller on a single-tenant deployment cannot address
another realm at all.

This is also the answer to the spike's sharpest objection — *what stops a relying party pinning
`iss` to a path the server never enforces?* Nothing about the path is decorative under this
rule: a request on the wrong realm path is refused. The path is neither authoritative nor
ornamental. It is a **redundant assertion that must agree**, which is what makes a per-realm
`iss` mean something without making the path a tenant source.

**Amendment: the topology D2 assumes.** D2 treats the header and the path as independent channels, but ADR-IAM-002 says a multi-tenant standalone origin gets its tenant from a load-balancer rule that sets a fixed header. With one fixed header per origin, each origin serves one tenant, and the path realm is a consistency check that adds no isolation. If the load balancer maps the path to the header, "must agree" is circular and the path is in effect what picks the tenant, which ADR-IAM-002 rejected. So the tenant boundary does not rest on the header. It rests on per-realm client authentication, per-realm credentials and keysets (D4a), and the token-layer binding (D4b). D2 is a guard against misrouting, not the isolation mechanism. A deployment that maps the path to the header at its edge must say so, and it gains nothing from D2.

**Amendment: path handling.** The realm is read from the matched route parameter, never by parsing the raw path. Encoded `/`, dot segments, matrix parameters and case variants of a realm segment are rejected. The forwarded-prefix setting stays off, so no proxy header can add or strip a realm prefix.

**Rejected alternatives.**

- **A2a — the path is authoritative for Enterprise; the header is dropped.** Rejected. It
  reverses ADR-IAM-002 for the topology with the least edge protection, and it makes tenant
  selection a caller-controlled string. It would also require restating the
  `TenantChokepointTest` / `TenantChokepointArchTest` guarantees, which currently rest on there
  being exactly one assertion point. Two assertion points with the weaker one winning is
  strictly worse than one.
- **A2b — the path is decorative and never checked.** Rejected. The server would advertise an
  `iss` claiming a realm scoping it does not enforce. This codebase already holds itself to
  *discovery never lies* (`OidcCapabilities`, `DiscoveryEndpointTest.everyAdvertisedEndpointIsServed`);
  publishing an issuer whose realm scoping is unenforced is the same defect in the one field a
  relying party trusts most.
- **A2c — merge, or first-match-wins, or one silently overrides the other.** Rejected outright.
  Any rule under which the two channels disagree and the request still proceeds is a
  tenant-confusion primitive, whichever side wins.

### D3 — `iss` becomes per-realm, derived by one function from one configured base; the anti-`Host` property survives verbatim

`iss` stops being a stored scalar and becomes a single pure derivation:

```
issuer(realm) = base                                  // baseline tier
issuer(realm) = base + "/realms/" + slug(realm)       // path-issuer tier
```

where `base` is `iam.oidc.issuer`, unchanged, still server configuration, still never
request-derived. **One definition, one place.** String concatenation at two call sites is how
the two issuer settings drifted apart in the first place.

**Amendment: the base-only issuer is allowed only in fixed-tenant mode.** Any deployment serving more than one tenant uses the per-realm form, whatever the tier. `sub` is unique only per `(tenant, baseline)` (V3), and both access-token mint paths set `aud` to the issuer, so with one shared `iss` the pair `(iss, sub)` no longer names one user (OIDC Core §2). A relying party that serves several tenants and keys accounts on `(iss, sub)` can then merge users from two tenants. The ID token carries the realm only when `profile` is granted, so it does not help. D4b closes this for introspection only; a relying party that validates tokens locally sees `iss` and `sub` and nothing else. Consequently, the "baseline tier" line above describes fixed-tenant mode, not a tier a multi-tenant deployment may choose.

**`DiscoveryEndpointTest.issuerIsConfiguredNotHost` generalises without weakening.** Today it
asserts the advertised issuer equals the configured constant under a spoofed `Host`. The
generalised property is that the advertised issuer equals `issuer(resolvedRealm)` under a
spoofed `Host` — and since the realm comes from the header or the fixed tenant and never from
the `Host`, the `Host` still cannot influence it. The anti-poisoning property is preserved
because it never depended on the issuer being *constant*, only on it being *not
request-derived*.

Concretely, and this matters: keep the existing test verbatim for the baseline case, and add
(a) a spoofed-`Host` case with a matching realm path, asserting the issuer derives from the
configured base rather than the `Host` authority, and (b) a spoofed-`Host` case with a
**mismatched** realm path, asserting the D2 rejection. Without (b) the generalisation quietly
converts "200 with the configured issuer" into "200 with whatever realm was asked for".

**`IssuerConsistencyCheck` is restated, not deleted.** Its exact scalar comparison can no
longer express the invariant. The property becomes: both sides derive from the same base
through the same function. `iam.keys.issuer` stops being an independently stamped scalar, the
key row's `issuer` column is populated with `issuer(realm)` at mint time, and the startup check
compares the configured bases.

> **Migration consequence, flagged because it is easy to miss.** V2 declares a selection index
> on `(tenant_id, issuer, key_use, state)`, but no query uses `issuer`: `DbKeyProviderAdapter`
> loads the tenant's rows under RLS and picks by `state` in `KeyRotationPolicy`. So changing the
> derivation does **not** orphan existing `ACTIVE` keys; it leaves their stamped `issuer` stale.
> The migration that bites is relying-party-facing: every new token's `iss` changes, and so does
> its `aud`, because both access-token mint paths currently set `aud` to the issuer. Backfill
> `signing_key.issuer` so the column stays truthful before anything starts selecting on it. See
> **OQ-3**.

**Rejected alternatives.**

- **A3a — keep one global `iss`; put the realm only in the endpoint paths.** Rejected. `iss`
  would then carry no tenant information, so the check a relying party is most likely to
  perform stays vacuous, and two tenants' tokens remain distinguishable by keyset alone —
  the single point of failure D4 exists to stop depending on.
- **A3b — a per-tenant subdomain issuer instead of a path.** Rejected on adopter cost; see
  *The adopter issuer split* below. It multiplies the DNS, certificate and internal-address
  problem by the tenant count, to buy a separation the path form already provides.

### D4 — No shared keyset in any tier, and add a second, independent tenant check in the token layer

**D4a — tenants never share signing key material.** Every tenant has its own keyset in every
tier. The tier buys issuer shape, rotation policy and discovery layout; it does not buy
isolation, because isolation is not a tier feature.

This inverts what the spike expected, and Findings 1 and 2 are the argument. Sharing removes
the only tenant boundary the introspection path has (Finding 1), and the clean form of sharing
is forbidden by RLS while the achievable form duplicates private key material (Finding 2). The
saving is fewer keys; the cost is tenant confusion.

To be fair to the rejected option: a shared keyset *could* be made safe, by building a second
boundary first. That would require adding a tenant claim to the token, comparing it to
`realm.tenant` in the introspector, comparing `iss` to `issuer(realm)`, and fixing both checks
in the port contract so no adapter can quietly drop them. But doing that work *in order to
remove* the boundary that already exists trades a mathematical property for a
correct-code property, for a benefit that Finding 2 shows cannot be realised cleanly.

**D4b — add the tenant claim and the `iss` comparison anyway, as defence in depth.** The token
should name its tenant, and `AccessTokenIntrospectorPort.verify` should reject a token whose
tenant claim or `iss` does not match the realm it is presented in, in addition to the signature
check. Then the boundary is two independent mechanisms rather than one.

D4b is the highest-value item in this spike and it **depends on nothing else here** — not on
the registry, not on tiering, not on path issuers. It is implementable and testable against the
current code today. It should be split out as its own item and should not wait for the tiering
work.

**Amendment: D4b compares the full realm.** The comparison is against the whole `RealmKey`, `(tenant, baseline)`, not the tenant alone. `DbKeyProviderAdapter.publishedJwks` selects keys by `realm.tenant()` only, so today an access token minted for `(T, B1)` introspects as `active` in `(T, B2)`. Refresh-token introspection already treats `(tenant, baseline)` as the isolation unit, and the two token types must agree.

**Amendment: D4b fails closed.** D4b is safe to ship first only with these rules:

- A token with no realm claims, no `iss` or no `exp` is `inactive`. Today `IntrospectService.introspectAccess` treats a token with no `exp` as active.
- Rollout is two-phase so a rolling multi-instance deploy does not reject valid tokens: first emit the claims on both mint paths, then wait one access-token TTL, then enforce.
- Until D3 ships, `iss` is the same for every tenant, so only the realm claims tell tenants apart; comparing `iss` adds separation only after D3.
- The realm claims are security claims. They are written after every claim contributor has run, under reserved names a contributor cannot set (`ClaimContributor` already writes `realm_tenant` on the profile path).

**Rejected alternatives.**

- **A4a — shared Starter keyset, with a tenant claim as the compensating control.** Rejected
  per above. Where a cryptographic partition and a parsed-claim check cost about the same,
  prefer the one that does not depend on a future maintainer not deleting a line.
- **A4b — shared keyset, isolation restored by scoping introspection client credentials.**
  Rejected. The realistic failure is a *confused* relying party, not a malicious one: an RP
  legitimately holding credentials in one realm, handed a token minted in another, gets
  `active` and acts on a foreign subject. Authenticating the introspecting client does not
  address a token that should never have verified. It is also weaker than it looks today: a public client introspects with its `client_id` alone, which makes introspection a token scanner for anyone within the realm (RFC 7662 §4). That is out of scope here, but it is recorded so it is not mistaken for a control.

### D5 — Per-realm discovery and JWKS for the path-issuer tier; the cache-TTL-vs-dwell timings stay global

Per-realm discovery is not optional once D3 holds: OIDC requires the discovery document at
`issuer + /.well-known/openid-configuration`, so a per-realm issuer implies a per-realm
discovery document and a per-realm JWKS route.

The publish-before-sign invariant — `jwks.cache-ttl-seconds` strictly below
`pending-dwell-seconds`, so a verifier's cached JWKS is guaranteed to expire before a `PENDING`
key ever signs — is **unchanged per keyset**, because each verifier caches per JWKS URI and
each keyset dwells independently. What changes is the number of independent rotation schedules.

**Decision: the two timings stay global even when keysets do not.** Keeping them global keeps
the invariant a two-scalar comparison that a single startup check can enforce. Per-tenant
timings would turn it into an N-way check with no natural place to run it and no natural place
to notice when one tenant's pair is inverted. Rotation load is already per-tenant shaped —
selection is per tenant under RLS, then by `state` — so N keysets are load, not redesign.

**Amendment: the dwell is enforced, not assumed.** `JwksCacheTtlVsDwellTest` checks cache TTL against dwell for the shipped configuration only, and nothing checks that a key actually dwells: `KeyRotationService.promoteToActive` has no time check, and `FirstBootProvisioner` promotes a key as soon as it is minted. `KeyRotationPolicy` refuses to promote a `PENDING` key before its dwell has elapsed, and a startup check asserts TTL < dwell for the running configuration. First boot is the one exception, because no verifier can hold a cached JWKS yet, and it is named as such.

**Amendment: responses are not cached across tenants.** JWKS and discovery responses are `Cache-Control: public`, and in header mode they are selected by `X-Tenant-Id` on a shared URL with no `Vary` header, so a shared cache can serve one tenant's keys or metadata to another. Every multi-tenant deployment either sends `Vary: X-Tenant-Id` on these responses or serves them only on per-realm URIs.

### D6 — What is deliverable without a messaging layer: everything here

The spike carried the messaging question as a shared upstream gate. Under D1 it largely
dissolves for this path. If the registry is the source of truth and is written
administratively, then a tier change **is** that write — synchronous, transactional, with no
consumer to react to it.

Deliverable now, in dependency order: the registry table and its narrow port with the asserted
arch-test exemption (D1); the tenant claim and `iss` comparison (D4b, independent, first); the
two-channel reject rule (D2); the per-realm issuer derivation with the generalised discovery
tests and the restated startup check (D3); the per-realm discovery and JWKS routes (D5).

Not deliverable, and unchanged: reacting to a tier change that *originates outside* tessera.
That only becomes the critical path if the tier must be owned by an upstream system rather than
by this registry. The adopt-messaging question itself is untouched and remains out of scope.

---

## The adopter issuer split

The task asks how this bears on the adopter problem where one issuer URL cannot mean the same
thing to a browser reaching a published port and to a gateway container reaching an internal
host.

An issuer is an **identifier compared character-for-character** (OIDC Core §3.1.3.7), not an
address — `IssuerConsistencyCheck`'s javadoc already says so. The split is that two callers
reach the same server at different authorities while discovery advertises exactly one.

A path-scoped issuer does not fix that, because the split is in the authority. It bears on it
twice, once helpfully and once not:

- **It keeps the problem singular.** Path realms keep every tenant on one origin, so an adopter
  solves the authority split once, for one hostname and one certificate. A per-tenant subdomain
  issuer (A3b) makes it a per-tenant DNS, certificate and internal-address problem that grows
  with the customer list. This is the main argument for the path form over the subdomain form.
- **It enlarges the string that must match.** Every derived endpoint URL now carries the realm
  prefix too. Any workaround that rewrites the authority at a proxy must preserve that prefix
  byte-for-byte; a proxy that strips or adds a path prefix breaks the issuer match, and that
  breakage surfaces only at the relying party with no local signal — the same failure mode
  `IssuerConsistencyCheck` was written to catch at startup.

**Recommendation:** the issuer is the publicly reachable identifier, and an in-cluster caller is
configured to *resolve that identifier* (split-horizon DNS, or a host alias) rather than to
fetch from an internal URL and trust a different `iss`. This is an infrastructure decision, and
it is recorded here for the same reason ADR-IAM-002 recorded the multi-tenant load-balancer
point: so it is not later mistaken for a code gap that a future change quietly "fixes" by
trusting a request-derived value.

---

## Threat model

| Threat | What answers it | Residual |
|---|---|---|
| **Tenant confusion** — a token minted for one tenant accepted in another | D4a keyset partition, D4b full-realm claim and `iss` comparison, D2 mismatch rejection, and for local validation and ID tokens a per-realm `iss` in every multi-tenant deployment (D3 amendment) | An RP that introspects in the wrong realm now gets a correct `inactive`, which may present as an availability problem rather than a security one |
| **Cross-tenant caching of keys or metadata** | `Vary: X-Tenant-Id` or per-realm URIs (D5 amendment) | A shared cache that ignores `Vary`; per-realm URIs are the robust form |
| **Issuer spoofing via `Host`** | Unchanged: the issuer derives from configuration, never from the request (D3); the existing test is kept verbatim and extended | None known |
| **Issuer spoofing via the new path channel** | D2: the path cannot select a realm, so no token can be minted under a realm the caller merely asked for | An attacker able to register a slug visually close to a victim's — see OQ-1 |
| **Tier escalation** | D1: tier is read from an administratively written registry, never from a request header or claim; the runtime role has no write privilege on it (D1 amendment) | Compromise of the separate administrative role; out of scope here |
| **Key custody across tiers** | ADR-001's single provider behind `KeyProviderPort` | N keysets multiply the custody surface. ADR-001's D3 asks for a budget line on sign-request cost and provider throttling; under D4a that line must be re-run against tenants × keys-per-tenant, and against the provider's **key-count** quota, not only its request rate. Per-tenant keysets still share one envelope key-encryption key or KMS key, so D4a separates keys logically under a single custody root |
| **Registry read as an RLS bypass** | D1's narrow port, plus an enumerated allowlist in an arch rule that covers the whole persistence layer (D1 amendment) | The exemption exists by design. Its value depends entirely on it being enumerated; with the rule widened, moving a class to another persistence package no longer hides it |

---

## Consequences

**Positive.** The introspection tenant boundary stops being a single point of failure. The
registry gives tier, slug and lifecycle one home with one write path. Per-realm issuers are a
config and startup-check change, not a schema change (Finding 4). D4b is independently
valuable and independently shippable. The messaging dependency leaves this path's critical line
(D6).

**Negative / accepted.** A new cross-tenant persistence root exists, exempt from the RLS policy
that protects everything else — bounded, but real. Keysets, rotation schedules, JWKS documents
and discovery documents all become per-tenant, multiplying operational load and key-custody
surface. The issuer derivation is a migration for any existing deployment (OQ-3). The path
realm enlarges the string adopters must preserve byte-for-byte across proxies.

---

## Closing note — sequencing and candidate splits

The follow-on work, as input for splitting the tier-driven issuer topology and
lifecycle-consumer item. Sizes are S/M/L shape only; points belong to the backlog owner. That
item's acceptance criteria are partly contradicted: "Starter: shared keyset, tenant carried by
a `tenant_id` claim" is rejected by D4a, so rewrite them against A, B and C below.

**Sequencing: the token-layer tenant binding (D4b) goes first, alone, and may start before
ratification.** This confirms the earlier read. It closes Finding 1's single point of failure on
today's single-issuer topology. It depends on no Proposed decision, whereas every other item
waits on D1 or OQ-1. And D4 wants two independent boundaries before any tiering work touches
keys. One revision: put the comparison in `IntrospectService`, not `JwsAccessTokenIntrospector`.
The adapter returns claims and the application layer rejects a mismatch, which is how "no
adapter can quietly drop it" is enforced in practice. Then the registry (D1), then the
path-scoped issuer work (D2, D3, D5). The lifecycle consumer is off this path entirely (D6).

**Candidate A — access-token tenant binding (D4b). Size S. Depends on nothing.** Every access
token carries its realm, and introspection returns `inactive` when the claimed realm or `iss`
disagrees with the realm it is presented in. Reuse `realm_tenant` and `realm_baseline`, which
the ID token already emits under `profile`, rather than inventing `tenant_id`. On the access
token they are unconditional: a security claim, not a profile one. Both mint paths need it, the
token service and the refresh service, or refreshed tokens go `inactive` when the check ships.
`VerifiedAccessToken` gains `iss` and the realm claims. `issuer(realm)` is the configured
constant today, so D3 later changes only the function behind the check. The comparison covers the baseline too (D4b amendment), and a token without the claims is `inactive` once enforcement starts; the two-phase rollout keeps pre-deploy tokens from being rejected mid-deploy. The original item never scoped this, so it may fit better as a
sibling than a carve-out.

**Candidate B — tenant registry with fail-closed refusal (D1). Size M. Depends on
ratification and OQ-4; on OQ-1 only if the slug ships here.** It delivers the `tenant` table
outside per-tenant RLS, the narrow read port, and the by-name exclusion in
`TenantChokepointArchTest`. An unregistered tenant gets no token. A `status` column makes a
suspended tenant get none either, which delivers the original "suspended tenant fails closed"
intent with no messaging. It needs an administrative write path and a migration registering
existing tenants, the single-tenant fixed tenant and the dev seed, or upgrade refuses everyone.
If OQ-1 is still open, ship tier and status here and add the slug with Candidate C.

**Candidate C — path-scoped issuer topology (D2, D3, D5). Size L; split again before
committing.** Depends on B for slug resolution and on OQ-1 to OQ-3. It splits by extension into
three pieces: the realm-mismatch rejection in `TenantResolutionFilter` with the chokepoint tests
extended; the issuer derivation, restated `IssuerConsistencyCheck`, generalised discovery tests
and `signing_key.issuer` backfill; and the per-realm discovery and JWKS routes. The last should
add the startup check and dwell enforcement from the D5 amendment; `JwksCacheTtlVsDwellTest` covers only the shipped configuration today.

**The `tenant.lifecycle.changed` consumer is not a candidate, nor a spike for this work.**
Tessera has no messaging layer: no reactive-messaging or Kafka dependency, no `@Incoming`,
`@Outgoing` or `Emitter`. Under D1 and D6 a tier or status change is a registry write, and B
already makes suspension fail closed. The consumer matters only if an upstream system comes to
own tenant lifecycle. Adopting messaging is one upstream decision, shared with consumer-side
tenant propagation; any spike belongs to that decision, serving both. Recommended: remove the
consumer from the implementation item and park it behind that decision.

---

## Open decisions

- **OQ-1 — the slug namespace.** Whether the path segment is a customer-chosen slug or a
  server-minted opaque identifier. A customer-chosen slug is a namespace with squatting,
  homograph and reuse-after-deletion problems, and it appears inside `iss`, which relying
  parties compare character-for-character and may pin indefinitely. Reuse of a deleted
  tenant's slug is the sharpest case: it makes a new tenant indistinguishable from an old one
  to any RP holding a pinned issuer. Deliberately left open — it is a product decision with a
  security tail, and it should not be settled inside an engineering ADR. **Amendment: a security floor holds whichever way it is decided.** Slugs are lowercase ASCII only, never `xn--` (punycode), never a reserved name, and never reassigned: a deleted tenant's slug is tombstoned.
- **OQ-2 — does the base JWKS serve Enterprise keys?** Serving them keeps relying parties that
  hard-coded the base URI working. Not serving them prevents a base JWKS that returns every
  tenant's keys from re-creating shared-keyset confusion at the verification layer for any RP
  that does not check `kid` provenance. **Recommended: no** — the base JWKS serves only the
  base realm. Open because it has a migration cost for existing integrations.
- **OQ-3 — upgrade path for an existing single-tenant deployment.** Whether its issuer changes
  shape at all, and the backfill of `signing_key.issuer` (D3). An issuer that changes shape is
  an issuer change, and today an audience change too, which every relying party must be told
  about.
- **OQ-4 — is tier per tenant or per realm?** `RealmKey` is `(tenant, baseline)`, and keys,
  clients and discovery are all realm-scoped, but the spike frames tier as a tenant property.
  **Recommended: tier is per tenant and applies to all its baselines.** Open because nothing
  in the code forces it, and two baselines of one tenant differing in tier would break the
  model in a small, easily-missed way.

---

## Exit criteria status

| Spike exit criterion | Status |
|---|---|
| ADR committed, states the tier source | D1 — a registry table outside per-tenant RLS, administratively written, unknown tenant refused. **Requires ratification.** |
| States the two-channel resolution rule | D2 — header/fixed tenant is the sole source; a path realm must agree or the request is rejected in `TenantResolutionFilter`. Stated as a pinnable invariant. |
| States the Starter shared-keyset consequence | D4 — **no shared keyset in any tier**, inverting the spike's expectation. Findings 1 and 2 are the argument. |
| `iss` single value vs per-realm, anti-`Host` property preserved | D3 — per-realm by derivation from a configured base; the anti-`Host` property survives because it never depended on the issuer being constant. |
| Per-realm discovery / JWKS; TTL-vs-dwell invariant | D5 — per-realm routes; timings stay global so the invariant stays a two-scalar check. |
| What is deliverable without messaging | D6 — all of it. Under D1 a tier change is an administrative write with no consumer. |
| Implementation item re-pointed and split | **Input produced; tracker change pending.** The closing note gives the sequencing (D4b first) and candidate splits A–C, and recommends removing the lifecycle consumer. The backlog owner makes the tracker change. No production code was touched. |
