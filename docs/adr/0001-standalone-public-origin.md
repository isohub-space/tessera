# 0001 — Tessera is a standalone public origin, not a service behind an app gateway

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-09-17 |
| Issue | [#87](https://github.com/isohub-space/tessera/issues/87) |
| Affects | deployment topology, tenant resolution at ingress, first-boot provisioning |

---

## Context

Tessera's tenant contract was written for a deployment with a gateway in front of it. Every
tenant-scoped route — `/authorize`, `/token`, `/introspect`, `/revoke`, discovery, JWKS, and
the `/login`, `/consent`, `/logout` endpoints — reads a gateway-asserted `X-Tenant-Id` and
fails closed without one. That expectation is stated in `TenantHeaders`, and the fail-closed
part of it is real and not in question here.

The open question was *which* gateway. The obvious candidate in a platform that already runs
one is the application gateway that fronts the product's own back-end services: a
deny-by-default reverse proxy with a curated route table, which authenticates an existing
session and proxies it onward.

That is the wrong shape for an authorization server, for a reason that is structural rather
than a matter of configuration:

- `/authorize`, `/login`, `/consent`, `/logout`, and `/token` for public PKCE clients must be
  reachable by the **end user's own browser, before that user is authenticated by anything**.
  By the time a browser arrives at tessera there is, by definition, no session — so a gateway
  whose job is to authenticate a session has nothing to authenticate, and the request it is
  asked to protect is the request that creates the very thing it checks for.
- Discovery and JWKS must additionally be reachable by **any relying party's backend as a
  plain HTTP client**, including that same application gateway once it starts trusting tessera
  as its identity provider.
- Between those two, nearly tessera's entire route surface would have to be allow-listed
  anyway, which empties the deny-by-default posture of its meaning while keeping its cost.

The relationship an application gateway actually wants with an identity provider is the one it
already has with whatever provider it uses today: it is the provider's **OIDC relying party /
client** — it redirects the browser out to the provider, and calls the token and introspection
endpoints server-to-server. That is a sibling, not a parent.

## Decision

**Tessera is deployed as its own public origin on a dedicated subdomain** (for example
`iam.example.com`), with its own domain mapping and certificate, alongside the application
gateway rather than behind it. The gateway is tessera's client.

There is then no proxy hop that could assert `X-Tenant-Id`, so the tenant has to be
established some other way. For the single-tenant deployment that a first rollout actually is,
that is settled **in tessera itself**, not at the edge: with `iam.tenancy.fixed-tenant` set,
`TenantResolutionFilter` binds every tenant-scoped request to that tenant at the zero baseline
and ignores the tenant and baseline headers entirely, so a caller cannot select another tenant
by sending one. A malformed value refuses to boot rather than silently serving no tenant.

## Consequences

### What this forced, and what now carries it

| Concern raised by having no proxy in front | How it is answered |
|---|---|
| Nothing asserts `X-Tenant-Id` | `iam.tenancy.fixed-tenant` (`TESSERA_FIXED_TENANT`) — headers ignored, not merged |
| Discovery/JWKS must answer an anonymous relying-party backend | Same: in fixed-tenant mode those routes resolve with no header at all |
| `X-Subject-Id` arrives straight from the public internet | `iam.subject.trust-header` defaults to `false`; `SessionCookieFilter` strips any inbound value, and a verified session cookie is the only way to establish a subject |
| A fresh origin has an empty database and nobody can sign in | `iam.bootstrap.*` first-boot provisioning of the signing key, one client and one user — idempotent, secrets from the environment |
| The issuer must match the public origin | `TESSERA_OIDC_ISSUER` is set to it, and the signing-key issuer must resolve to the same value — otherwise discovery, minted tokens and key material disagree in a way that surfaces only at the relying party |
| The relying party's own login page is cross-origin | `TESSERA_CORS_ORIGINS`, against the deny-by-default CORS policy |

### What it leaves open

- **Multi-tenant on a standalone origin is not solved in code.** There is no hostname- or
  path-derived tenant resolution; a missing header is still a hard `400` whenever
  `iam.tenancy.fixed-tenant` is unset. A deployment serving more than one tenant without a
  proxy needs the tenant asserted at whatever load balancer terminates TLS for the origin —
  a fixed custom-request-header rule, which an external HTTPS load balancer supports natively.
  That is an infrastructure decision; it is recorded here so it is not mistaken for a code gap
  that a future change quietly "fixes" by trusting a client-supplied value.
- **Forwarded-header trust is weaker on a public origin than it was behind a gateway.**
  `quarkus.http.proxy.trusted-proxies` is left unset (see the comment in
  `application.properties`), so `X-Forwarded-For` is whatever the caller sent. The rate
  limiter treats source IP as a secondary axis for this reason — except on `/login`, which has
  no client identifier to key on and is therefore IP-only, so its ingress bucket is evadable by
  a caller that varies the header. Per-account credential guessing is still bounded by the
  separate `(tenant, username)` failure budget, so this is a weakened outer tier rather than an
  open door — but it is a consequence of this decision and wants its own change.

## Alternatives considered

- **Behind the application gateway, with the pre-auth routes allow-listed.** Rejected: the
  allow-list would cover nearly the whole surface, the gateway cannot authenticate a caller
  who is by definition not yet authenticated, and it puts a session-proxying hop in the path of
  the flow that mints sessions.
- **Deriving the tenant from the request host or path.** Rejected for now: it moves a
  security-load-bearing decision into string handling over a value the caller controls, to
  serve a multi-tenant standalone deployment that does not exist yet. A fixed tenant chosen by
  configuration cannot be influenced by a request at all, which is the stronger property while
  one tenant is all that is being served.
- **Trusting a client-supplied `X-Tenant-Id` when no gateway is present.** Rejected outright:
  on a public origin that is tenant selection by the attacker.
