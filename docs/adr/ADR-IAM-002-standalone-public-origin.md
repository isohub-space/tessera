# ADR-IAM-002 — Tessera is a standalone public origin, not a service behind an app gateway

| Field | Value |
|---|---|
| Status | **Accepted** |
| Date | 2026-09-17 |
| Ratified | 2026-10-19 (confirmed unchanged) |
| Issue | [#87](https://github.com/isohub-space/tessera/issues/87) |
| Relates to | [ADR-IAM-003](ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md) (multi-tenant issuers), [ADR-IAM-004](ADR-IAM-004-end-user-session-and-consent.md) (session and consent) |

---

## Background

Tessera's tenant contract assumed a gateway in front of it. Every tenant-scoped route reads a gateway-asserted `X-Tenant-Id` and fails closed without one: `/authorize`, `/token`, `/introspect`, `/revoke`, discovery, JWKS, `/login`, `/consent` and `/logout`. That fail-closed rule stays.

The obvious gateway is the application gateway that fronts the product's own back-end services. It is a deny-by-default proxy that authenticates an existing session and passes it on. That is the wrong shape for an authorization server:
- The user's own browser must reach `/authorize`, `/login`, `/consent`, `/logout`, and `/token` for public PKCE clients before anything has authenticated the user. A gateway that checks sessions has nothing to check on the request that creates the session.
- Any relying party's backend must reach discovery and JWKS as a plain HTTP client. That includes the application gateway itself, once it trusts tessera.
- Together, nearly every tessera route would have to be allow-listed. That empties the deny-by-default posture while keeping its cost.

An application gateway's natural relationship with an identity provider is that of an OIDC client. It redirects the browser to the provider and calls the token and introspection endpoints server to server. It is a sibling, not a parent.

## D1 — Tessera is its own public origin

**Decision.** Tessera runs as its own public origin on a dedicated subdomain (for example `iam.example.com`), with its own domain mapping and certificate, next to the application gateway rather than behind it. The gateway is a tessera client.

**What it means.** With no proxy to assert `X-Tenant-Id`, a single-tenant deployment settles the tenant inside tessera. With `iam.tenancy.fixed-tenant` set, `TenantResolutionFilter` binds every tenant-scoped request to that tenant at the zero baseline and ignores the tenant and baseline headers. A caller cannot select another tenant. A malformed value stops the server at startup.

**Consequences.**
1. Nothing asserts `X-Tenant-Id`. `iam.tenancy.fixed-tenant` (`TESSERA_FIXED_TENANT`) answers this: the headers are ignored, not merged.
2. Discovery and JWKS must answer an anonymous relying-party backend. In fixed-tenant mode they resolve with no header.
3. `X-Subject-Id` arrives straight from the internet. `iam.subject.trust-header` defaults to `false`, `SessionCookieFilter` strips any inbound value, and only a verified session cookie establishes a subject.
4. A fresh origin has an empty database, so nobody can sign in. `iam.bootstrap.*` provisions the signing key, one client and one user at first boot. It is idempotent and takes its secrets from the environment.
5. The issuer must match the public origin. `TESSERA_OIDC_ISSUER` is set to it, and the signing-key issuer must resolve to the same value.
6. The relying party's login page is cross-origin. It is allowed through `TESSERA_CORS_ORIGINS`, against the deny-by-default CORS policy.
7. This record does not solve multi-tenant on a standalone origin. Without `iam.tenancy.fixed-tenant`, a missing tenant header is still a `400`. A deployment serving several tenants without a proxy needs the tenant asserted at the load balancer that terminates TLS, for example by a fixed custom request header. That is an infrastructure choice. It is recorded so that nobody "fixes" it later by trusting a client-supplied value. ADR-IAM-003 covers per-tenant issuers.
8. Forwarded headers are weaker on a public origin. `quarkus.http.proxy.trusted-proxies` is unset, so `X-Forwarded-For` is whatever the caller sent, and the rate limiter treats source IP as a secondary axis. `/login` has no client identifier and is limited by IP only, so a caller can evade its ingress bucket by varying the header. The separate failure budget per tenant and username still bounds password guessing. This weaker outer tier needs its own change.

## Rejected alternatives

- **Behind the application gateway, with the pre-authentication routes allow-listed.** The allow-list would cover nearly everything, and the gateway cannot authenticate a caller who is not yet authenticated.
- **Derive the tenant from the request host or path.** Rejected for now. It moves a security decision into string handling over a value the caller controls, to serve a multi-tenant standalone deployment that did not exist. A fixed tenant set by configuration cannot be influenced by a request at all.
- **Trust a client-supplied `X-Tenant-Id` when no gateway is present.** On a public origin that lets the attacker choose the tenant.
