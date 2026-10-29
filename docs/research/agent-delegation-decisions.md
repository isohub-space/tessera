# Agent delegation, part two: intermediaries, hand-offs, revocation, actor identity, MCP, and the configuration points

| Field | Value |
|---|---|
| Date | 2026-10-29 |
| Status | Decided by the maintainers on 2026-10-29 (autonomous roots on 2026-10-30). The proposed ADR-IAM-007 is rewritten against this note. |
| Question | How does an agent chain handle gateways and MCP servers, sub-agent hand-offs, revocation of self-contained tokens, actor identity across tenants and baselines, the `actor_token`, and stock MCP clients, without any configurable choice that can make tessera less secure? |
| Builds on | [Agent delegation profile](agent-delegation-profile.md) (D1 to D6), [Agentic IAM landscape, October 2026](agentic-iam-landscape-2026-10.md), the proposed ADR-IAM-007, [ADR-IAM-003](../adr/ADR-IAM-003-tenant-tier-and-path-scoped-issuer.md), [ADR-IAM-004](../adr/ADR-IAM-004-end-user-session-and-consent.md), [threat model](../security/threat-model.md) rows 18 to 25 |
| Source state | Code references are at `main` commit `09189b2`. Specification status was checked on 2026-10-29. |

## Background

The first design note and the proposed ADR-IAM-007 settle the single-hop exchange: the actor is the authenticated client, every hop attenuates, every delegated token is bound, and revocation goes through a lineage store. This note settles what they left open, in nine decisions, and fixes how tessera offers a choice at all.

The maintainers' rule for every configuration point: **a choice is configurable only if none of its states weakens security, and every configuration point declares its states and their consequences.** A state below the security floor below is not offered, however useful it would be for interoperability.

Path abbreviations: `api/` = `tessera-api/src/main/java/dev/tessera/iam/application/`, `dom/` = `tessera-domain/src/main/java/dev/tessera/iam/domain/`, `rest/` = `tessera-rest/src/main/java/dev/tessera/iam/adapter/rest/`, `pers/` = `tessera-persistence/src/main/java/dev/tessera/iam/adapter/persistence/`, `mig/` = `tessera-persistence/src/main/resources/db/migration/`, `props` = `tessera-server/src/main/resources/application.properties`.

## The security floor

Every state of every configuration point keeps all five properties. A state that loses one is dropped.

1. **Key-authenticated actor.** Whoever becomes an actor proves possession of a key that tessera associates with a registered client: `private_key_jwt`, a workload credential that carries a key (`cnf`) or comes from an issuer that enforces single use with a `jti`, or RFC 8705 mTLS once it is real client authentication over TLS that tessera terminates or an authenticated edge hop.
2. **Sender-constrained tokens.** Every access token tessera issues to an agent, every token carrying `act`, and every subject token of an exchange is bound to a key the presenter proves to tessera cryptographically (`cnf.jkt` with DPoP, or `cnf["x5t#S256"]` from a certificate tessera can trust). A one-time grant artefact (an authorization code, a hand-off token) may instead be bound to a key-authenticated client, as RFC 6749 binds a confidential client's code to its authentication.
3. **Single use** of hand-offs, client assertions and forwarded proofs, across instances and realms.
4. **Realm isolation.** No token, assertion, actor or chain crosses a `(tenant, baseline)` realm.
5. **Revocable chain.** Every delegated token is recorded in lineage, and the active check fails closed.

## The rule for configuration points

- **Ordered states.** Each point's states are totally ordered from the default upwards. No state is below the floor.
- **Deployment value and client value.** The operator sets a deployment minimum. A client registrant may set a stricter value for its own client. The effective value is the stricter of the two.
- **Only the operator lowers.** A stored per-client value can be lowered only by the operator, as an audited security event. Lowering the deployment minimum does not lower clients whose stored value was set under the higher minimum. A client without a stored value follows the deployment minimum down as well as up, and lowering the minimum is itself an audited event.
- **Chain monotonicity.** A hop's effective level is at least the effective level of the token it derives from. A delegation grant (set by the person or the operator) may carry a minimum. An exchange or redemption is refused with `invalid_client` when the actor cannot meet the highest of the deployment minimum, its own value, the parent hop's level and the grant minimum.
- **The level travels in the token.** The effective level of each hop is stamped into its `act` object, so a resource server, which cannot read another client's registration, can require a minimum per tool, as it would use `acr` for a person.
- **Fail at startup.** An unknown state name, or a value outside the declared bounds, fails startup; nothing is clamped silently. A state marked "later" is an unknown name until the change that implements it ships. A stored per-client value outside the declared states is refused when it is written and treated as `invalid_client` when it is used.
- **Capability caps read the other way.** Where the stricter state is "off" (the intermediary), the point is an operator allow-list per registered client, not a minimum a client raises.

## What the code establishes

These facts were traced on `main` at `09189b2` and shape the decisions.

- `/token` dispatches on grant-type strings (`rest/TokenResource.java:63-66,119,173-175`), so the sealed `GrantType` (`dom/client/grant/GrantType.java:19-20`) guards registration parsing and per-client grant checks, not the endpoint.
- Consent is stored but not enforced: `ConsentService.hasConsented` (`api/ConsentService.java:29-31`) has no caller, and the authorization-code grant records whatever scopes the request names (`api/AuthorizationService.java:75`; `api/ClientRequestCheck.java:31-45` checks only grant and redirect URI).
- The realm comes from `X-Tenant-Id` / `X-Baseline-Id` in multi-tenant mode (`rest/tenancy/TenantResolutionFilter.java:84-88`). The client certificate comes from `X-Client-Certificate` (`rest/token/ClientCertificateThumbprint.java:33`; `rest/TokenResource.java:92,129,169`) with no trust switch, even in fixed-tenant mode (`props:159-166`).
- A client assertion's `aud` is the one global issuer (`rest/token/NimbusClientAssertionVerifier.java:131,240-241`), its spent `jti` is keyed per realm for `private_key_jwt` (`rest/token/AssertionReplayStore.java:61`; `NimbusClientAssertionVerifier.java:194-195`), and the verifier does not check the JWS `typ` header (`NimbusClientAssertionVerifier.java:159-163` reads only `alg` and `kid`). A workload-identity token is reusable until `exp` unless its issuer enforces single use (`:186-196`).
- DPoP proofs are accepted only from public clients on the authorization-code grant, and a public client without one is refused (`api/TokenService.java:271-287`). The validator checks `typ`, `alg`, `jwk`, signature, `htm`, `htu` by exact equality with one configured URL, `iat` and `jti` (`rest/token/NimbusDpopProofValidator.java:76-131`); it has no `ath` check and no nonce. Its replay map is keyed by `jti` alone, uncapped, pruned by a full scan per proof (`:50,127-130,148-150`). `proofMaxAge` and `clockSkew` have defaults but no upper bound (`rest/config/DpopConfig.java:24-33`).
- With `iam.authflow.require-sender-constraint=false` a confidential non-mTLS client receives an unbound Bearer token (`api/TokenService.java:288-297`; `api/ClientCredentialsService.java:157`; default `true` at `props:188`). Refresh re-mints an unbound Bearer token with no scope (`api/RefreshService.java:275-292`).
- Access-token lifetimes have no upper bound: only `requirePositive` (`api/TokenService.java:132,406-411`).
- Introspection reports `token_type` `Bearer` and no `cnf` for every access token, treats a token without `exp` as active, and is open to any public client by `client_id` (`api/IntrospectService.java:72,113,116-117`). `/revoke` is a no-op for a JWT (`api/RevokeService.java:77-81`).
- The issuer is one configured string on every mint path (`rest/config/UseCaseProducer.java:111,151,205`); a client identifier is unique only per `(tenant, baseline)` (`mig/V3__iam_core_entities.sql:55`); keysets are per tenant only.
- Nothing in main code handles `dpop_jkt`, `dpop_bound_access_tokens`, `resource` at `/authorize`, or the RFC 9207 metadata flag, although `iss` is emitted on authorization responses (`rest/AuthorizeResource.java:196,199`).

## Decision 1: what lineage records

**Rule.** The lineage store records every token tessera mints that carries `act`, hop-1 agent tokens included, every autonomous root, and every hand-off token. An autonomous root is a `client_credentials` token minted for a registered agent client under an operator-configured grant; it carries no `act`, and a same-actor exchange from it compares its `client_id` with the authenticated client (decided on 2026-10-30, so that autonomous chains keep a recorded root). The active check of an exchange and of introspection fails closed for recorded tokens: a miss or a store error is inactive. Unrecorded tokens without `act` are never subject tokens, and keep signature, `exp` and realm checks (ADR-IAM-003 D4). Recording every access token is a later, separate decision.

**Why.** It covers everything a delegation chain can touch without deactivating today's unrecorded `client_credentials` and non-agent tokens.

**Requires.** A `delegated_token` table under the RLS idiom (`mig/V1__iam_rls.sql:39-43`) with `jti`, `parent_jti`, `root_jti`, `grant_id`, `refresh_family_id`, `actor_client_id`, the permitted resource set, the effective levels, `expires_at`, `revoked_at` and `consumed_at`; a lineage port with `record`, `isActive`, `revokeSubtree`, `revokeByGrant`, `revokeByActor` and `consumeOnce`; a database adapter and an in-memory twin; the operations added to `ReadRetryScopeArchTest`; a scheduled cleanup (none exists for any table today).

## Decision 2: who may revoke

**Rule.** A delegated token and its subtree may be revoked by the subject, the root client, any ancestor actor in its chain, and its own holder; nobody else. Withdrawing a grant deactivates every token issued under it, including child grants (decision 9). Disabling a client deactivates every recorded token whose chain contains it and refuses its exchanges. These are documented as tessera extensions of RFC 7009, whose §2.1 lets only the client a token was issued to revoke it. Cascade is by grant id and by a per-root epoch, each one indexed update, with caps on live children per parent `jti` and per grant and per-tenant quotas, so the store cannot be made a denial-of-service lever.

**Why.** A parent must contain a rogue sub-agent without killing its own token, and a compromised agent serving many people must be stoppable in one action.

**Requires.** JWT parsing, verification and the authority rule in `api/RevokeService.java`; `revokeByActor` wired to client disable; `act`, `aud`, `iss`, `cnf` and the true `token_type` in the introspection response (`api/port/out/AccessTokenIntrospectorPort.java:44-50`, `rest/dto/IntrospectionResponseDto.java`); introspection of recorded tokens only by authenticated confidential clients.

## Decisions 3 and 4: how an actor is named

**Rule.** From the first delegated token, `act.iss` is the realm's issuer URL that ADR-IAM-003 D3 will make the token issuer, `base/realms/<opaque id>`, and the namespace unit is one realm per `(tenant, baseline)`, so each baseline gets its own opaque id. Actors are compared by the pair `(act.iss, act.sub)` everywhere: cycle check, `may_act` reconciliation, chain monotonicity, resource-server allow-lists. A chain whose actors span realms is refused. Every subject token must carry realm claims equal to the request's realm and be recorded in lineage (a hop-1 agent token, an autonomous root, an exchanged token or a hand-off token); a token without `act` that is not recorded is never a subject token. The token's own `iss` stays global until the per-realm issuer ships on its own track; actor identifiers, stored grants and allow-lists do not change when it does.

**Why.** Actor-profile §3.2 and §3.4 make `(act.iss, act.sub)` the actor identifier and allow `act.iss` to be a namespace rather than the token issuer; RFC 8693 §4.1 says the pair "might be necessary". Signatures cannot separate two baselines of one tenant (keysets are per tenant), and the code already treats `(tenant, baseline)` as the isolation unit (`api/RevokeService.java:85-89`, `api/IntrospectService.java:91-94`). A per-baseline namespace stops staging-to-production chains.

**Requires.** The smallest slice of ADR-IAM-003 D1 and D3 that delegation needs: a realm registry minting one opaque id per `(tenant, baseline)` (no table exists; M). ADR-IAM-003 D3 is amended from "per tenant" to "per `(tenant, baseline)`". An `Actor` value type with pair equality. Independently, the `private_key_jwt` spent set becomes global, keyed by the registered key's thumbprint and `jti`, closing one-assertion-per-realm replay (S).

## Decision 5: the `actor_token`, configuration point `exchange.actor-proof`

The actor of an exchange is the key-authenticated client. RFC 8693 §2.1 makes `actor_token` optional; actor-profile §6.4.1 accepts a client's own assertion as one, and §3.1 says the absence of an actor credential must not by itself make the client the actor. RFC 9449 §11.11 names a remaining gap: DPoP is bound to client authentication only by sharing the TLS tunnel, so a copied assertion can be paired with a DPoP key the client never held.

| State | Behaviour | Protects | Costs | Who picks | Default |
|---|---|---|---|---|---|
| `client-key` | An `actor_token` is accepted only if it is the client's own assertion: the same JWT as `client_assertion`, or a separate self-assertion signed by a registered key, with `iss = sub = client_id`; both `jti`s are spent atomically. Any other `actor_token` is refused with `invalid_request`. A workload credential qualifies only with `cnf` (its proof required) or from an issuer that enforces single use and requires `jti`. A client assertion's `jti` is spent on every authenticated attempt, refused ones included. | The floor: one credential per actor, no second stealable credential, no unkeyed workload token. | Interoperable with actor-profile §6.4.1 clients. A copied assertion can still be used once, with the copier's DPoP key, if it is intercepted before tessera sees it. | Operator (deployment minimum) | **Yes** |
| `client-attested-key` | As `client-key`, and the client assertion, signed by the registered long-term key, carries `cnf.jkt` naming a per-instance or per-task DPoP key; the DPoP proof's key must have that thumbprint. The long-term key never signs DPoP proofs. The assertion must carry an explicit assertion `typ`. mTLS meets this state only when the certificate comes from TLS tessera terminates or an authenticated edge hop. | Closes the RFC 9449 §11.11 gap: a copied assertion is bound to a key the copier does not hold. Keeps the long-term key in its current custody (for example a KMS) and keeps instance and task keys separate. | Clients add one claim to their assertion. S in tessera (one thumbprint comparison and a `typ` check). | Operator raises the minimum; a client registrant raises its own client | No |
| `attested-instance` (later) | As `client-attested-key`, and the DPoP key is proved to be an attested instance key: attestation-based client authentication in combined mode, with an attester distinct from the instance, or a WIMSE workload credential whose `cnf` key signs the proof. | Adds which instance acted, for shared agent platforms; two independent proofs. | Waits for the drafts; M to L. | As above | No |

**Ordering and chain.** `client-key` < `client-attested-key` < `attested-instance`. The chain rule above applies: a sub-agent's hop is at least its parent's level, and the effective level is stamped in each `act`.

**Errors.** `invalid_client` when authentication fails or the chain level cannot be met; `invalid_dpop_proof` when the proof's key does not match; `invalid_request` for a malformed or foreign `actor_token`. The assertion `jti` is already spent when `invalid_dpop_proof` is returned, so the distinct error tells an interceptor nothing it can reuse.

**Floor argument.** Every state requires a key-authenticated client and a bound output; the higher states only add checks and do not change key custody. In every state the assertion verifier refuses a JWT whose `typ` is `dpop+jwt`, the hand-off `typ` or the redeemer-key-statement `typ`; the redeemer key statement carries its own explicit `typ`, and its verifier accepts no other.

## Decision 6: hop 1 for MCP and agent clients (fixed rule)

**Rule.** No bearer state exists for delegation. Every access token issued to a client registered as an agent, every token carrying `act`, and every subject token of an exchange is sender-constrained (RFC 9700 §2.2.1). Concretely:

- `require-sender-constraint=false` is not available to clients registered as agents, to any token carrying `act`, or to any subject token; startup refuses `false` while the exchange grant is enabled.
- A refreshed token in these paths is never Bearer: refresh keeps `cnf`, scope and realm, or no refresh token is issued.
- Tessera mints a token carrying `act` for a resource only if that resource is registered as verifying sender constraint (the counterpart of RFC 9728's `dpop_bound_access_tokens_required`). The resource-server guide requires refusing a token with `cnf` presented as `Bearer`.

The bound paths are widened so that the cost falls without weakening anything:

- `dpop_jkt` at `/authorize` (RFC 9449 §10), declared with its caveat that the protection holds only with a unique DPoP key per authorization request.
- The `dpop_bound_access_tokens` client metadata (RFC 9449 §5.2) honoured at registration.
- `private_key_jwt` on the authorization-code grant, so a server-hosted MCP client can be confidential (MCP permits `private_key_jwt` for clients, 2026-07-28 client registration).
- `resource` at `/authorize`, the RFC 9207 `authorization_response_iss_parameter_supported` flag (a MUST for MCP when `iss` is emitted), and `revocation_endpoint` / `introspection_endpoint` metadata.
- A DPoP verifier with conformance vectors in the resource-server guide, since the MCP TypeScript SDK verifies no DPoP on the server side.
- A documented local bridge pattern: a stock stdio MCP client talks to a local bridge that performs OAuth and DPoP and keeps the key.

**Declared consequence.** MCP hosts that enable the TypeScript SDK's client DPoP support (2.1.0 and later) connect; other stock MCP clients connect only through the bridge pattern or as confidential clients. Revisit when MCP's DPoP profile (SEP 1932, with ext-auth pull request 33) is merged or the Python SDK ships client DPoP. When Client ID Metadata Documents are added later, a client's `jwks_uri` and web domain become a trust anchor for actor identity (domain takeover is actor impersonation), and threat row 17 (SSRF) reopens; both are declared with that change.

## Decision 7: the intermediary, configuration point `exchange.intermediary`

An intermediary (an MCP server or gateway acting as a resource server) receives a token whose `aud` is itself and must call a further API for the same person. RFC 8693 §4.1 and WIMSE AIMS §10.8 describe it exchanging that token; actor-profile §3.7.3 allows a presenter rebind without proof by the prior presenter, and its §13.3 accepts that rebind supersedes the input's binding. In a plain rebind tessera would trust the gateway's own proof-of-possession check: the one place in the profile where a binding is accepted on another party's word. The caller's own DPoP proof, which it already sends to the gateway, is the evidence that the call is live, and tessera can verify it itself.

This point is an operator allow-list per registered gateway; `off` is the stricter state.

| State | Behaviour | Protects | Costs | Who picks | Default |
|---|---|---|---|---|---|
| `off` | No intermediary exchange. Only same-actor exchange and hand-off redemption exist. | Everything; no laundering path. | Gateways that must call further APIs for the person cannot do so through tessera. | Operator, per gateway | **Yes** |
| `rebind-live-proof` | Presenter rebind, accepted only when all hold: the gateway authenticates by key (`exchange.actor-proof` applies); the subject token's single `aud` equals the gateway's operator-set registered resource identifier; the requested resource is in the downstream set the gateway declared at registration and the grant names (shown at consent); the caller's DPoP proof is forwarded as the profile parameter `subject_token_proof`, with `ath` equal to the hash of the exact subject token, a key whose thumbprint equals the subject token's `cnf.jkt`, `htu` equal to the registered resource or having it as prefix on a path-segment boundary after RFC 9449 normalisation, and an age of at most 60 seconds from `iat` under a ceiling fixed at startup; the proof's `jti` is spent in a shared, capped store keyed by `(realm, jkt, htu, jti)`, separate from token-endpoint proofs, atomically with the lineage record and also on refusal; at most one exchange per `(proof jti, resource)`; the subject token is active in lineage; mTLS-bound subject tokens are refused. The output is bound to the gateway's key, depth plus one, no refresh token, rate-limited per gateway. | Removes laundering of harvested tokens: a token whose caller is no longer sending requests yields no fresh proof and cannot be exchanged. Tessera re-establishes the input's binding itself. | Gateways forward one header value and follow the resource-server guide: a shared DPoP `jti` store and a server `nonce` (RFC 9449 §8), never logging the forwarded proof. Generic RFC 8693 intermediaries that do not forward the proof cannot use this path. M in tessera, including an `ath` check the validator lacks today. | Operator, per gateway | No |

**Declared residual.** While compromised, a gateway can obtain one downstream token per declared resource, at the subject token's full scope, for each user connected to it, renewed with each new inbound token, and it can solicit requests from connected clients to get fresh proofs. MCP uses one endpoint URL for every tool, so `htu` carries no per-tool intent. Tokens of callers no longer sending requests are safe. This equals what an honest gateway is allowed to do, which is inherent in naming it in the grant.

**Floor argument.** `off` keeps the floor trivially. `rebind-live-proof` keeps all five properties only with the `ath` check, the shared spent store and the lineage liveness check; each is pinned by a refusal test, including a live proof for another token under the same key.

## Decision 8: the hand-off token, configuration point `handoff.redeemer-binding`

**Fixed shape.** The hand-off is a JWT assertion grant in the actor-profile §4.1 shape, typed `urn:ietf:params:oauth:token-type:jwt` with its own explicit `typ`; `aud` is the issuer of the realm it is minted in: today the one configured issuer, `iam.oidc.issuer`, which is the only audience the assertion verifier accepts; once the per-realm issuer ships (ADR-IAM-003 D3), `base/realms/<opaque id>` for that `(tenant, baseline)` in multi-tenant mode and `base` in single-tenant mode, never another realm's issuer, not the token endpoint, matching tessera's issuer-only assertion audience (`rest/token/NimbusClientAssertionVerifier.java:76-81`); `sub` is the person; `act` is the parent's chain; `may_act` names the sub-agent by `(iss, sub)`; `jti` is single use, consumed in the lineage store across nodes; lifetime at most 60 seconds; scope and resource set are subsets of the parent's, and the resource set is recorded so the sub-agent's later exchanges stay inside it. Resource servers refuse it (RFC 9068 §4 requires `typ` `at+jwt`), and introspection reports it inactive.

| State | Behaviour | Protects | Costs | Who picks | Default |
|---|---|---|---|---|---|
| `client` | Redemption requires `may_act` to name the key-authenticated redeemer, single use and the 60-second lifetime; the output is bound to the key the redeemer demonstrates (actor-profile §6.5). A parent may raise a single hand-off to `client-and-key` by supplying a redeemer key statement. | The floor: the hand-off is a one-time artefact bound to a key-authenticated client, like a confidential client's authorization code. | Interoperable with the draft. A shared sub-agent service running many tasks can redeem one task's hand-off in another. | Redeemer's registrant; operator minimum | **Yes** |
| `client-and-key` | The parent forwards a redeemer key statement signed by the sub-agent's registered key: `iss = sub =` the sub-agent's `client_id`, `aud` = the issuer of the realm it is minted in: today the one configured issuer, `iam.oidc.issuer`, which is the only audience the assertion verifier accepts; once the per-realm issuer ships (ADR-IAM-003 D3), `base/realms/<opaque id>` for that `(tenant, baseline)` in multi-tenant mode and `base` in single-tenant mode, never another realm's issuer, `cnf.jkt`, a task nonce, `exp` at most 60 seconds, and its own explicit `typ`. Tessera verifies it when minting the hand-off, refuses one that does not name the `may_act` client, and spends the nonce. Redemption requires client authentication and a DPoP proof for that `jkt`; equality is checked, never copied; the output is bound to that key. Tessera never applies the draft's §13.3 rebind over a bound hand-off. | Stops task T2 of a shared sub-agent service from redeeming task T1's hand-off, and stops a parent substituting its own key (refused at minting). Holds per task only if the sub-agent uses a distinct DPoP key per task, which is declared. | Parent and sub-agent pass the statement in the request that asks the sub-agent to work; no standard field exists. S in tessera on top of the hand-off. | Redeemer's registrant raises; operator raises the minimum; a parent or grant minimum overrides a lower redeemer value | No |
| `attested-instance-key` (later) | As `client-and-key`, with the key proved to be an attested instance key (`exchange.actor-proof` `attested-instance`). | Instance-level assurance. | Waits for the drafts. | As above | No |

**Ordering and chain.** `client` < `client-and-key` < `attested-instance-key`, under the chain rule: each hop is at least its parent's level, the grant may set a minimum, the effective level is stamped in each `act`, only the operator lowers a stored value, and lowering the deployment minimum does not lower clients with a stored value; clients without one follow it, as an audited event.

**Required tests.** A redemption with valid sub-agent authentication and a proof for a key other than the hand-off's `jkt` is refused; so is one without a proof; a statement naming another client is refused at minting; a second redemption across nodes yields nothing.

## Decision 9: who may start a hand-off (fixed rule)

**Rule.** Only a key-authenticated actor may start a hand-off. DPoP is "not a client authentication method" (RFC 9449 §1): a public agent's key proves session continuity, not which registered client it is. A public agent reaches delegation in one of two ways. Later, attestation-based client authentication makes it a key-authenticated client. Today, the person delegates to the sub-agent directly: the sub-agent runs its own authorization-code flow, and the result is a **child grant** inside the parent's grant, naming the parent, with resources and scopes that are subsets of the parent's, counted in the parent's depth, and cascading when the parent's grant is withdrawn. The consent screen names the requesting parent and the limit.

**Why.** A sub-agent grant without the parent link would be a separate, wider grant with no cascade, and a compromised parent could use consent prompts as a phishing channel.

## Declared residuals

- **Confused deputy by prompt injection.** Content an agent reads can steer it to use rights it legitimately holds. Tessera bounds the blast radius (narrow grants, per-task approval, the resource server authorizing the pair `sub` and outermost `act.sub`); it cannot judge intent.
- **Cross-user mix-up inside a multi-user agent.** An agent that caches several people's tokens under one DPoP key can use the wrong one; tessera cannot see it.
- **Local validation window.** A resource server that validates JWTs locally sees a revocation only at expiry: at most 5 minutes from depth 2, and at most the hop-1 lifetime cap (below), whose value is declared with the cap. Irreversible operations introspect.
- **Lineage availability.** Fail-closed means a lineage-store outage stops delegation and introspection of recorded tokens.
- **Re-issuance upstream.** Revoking a link does not stop a compromised parent re-handing-off from its upstream refresh family; grant withdrawal, family revocation or the client kill switch does.
- **Copied assertion before use** in `exchange.actor-proof` `client-key`: closed by `client-attested-key`.
- **Shared task keys** in `handoff.redeemer-binding` `client-and-key`: the protection is per task only with per-task keys.
- **Compromised intermediary** in `rebind-live-proof`: as declared under decision 7.
- **Gateway-side replay of forwarded proofs**: mitigated by the resource-server guide's shared `jti` store and server `nonce`.
- **Co-located factors.** A workload credential, a DPoP key and a subject token on one host are not independent against host compromise.
- **Stock MCP clients without DPoP** cannot connect except through the bridge pattern or as confidential clients.

## Rejected alternatives

- **Plain rebind for intermediaries (no caller proof).** It accepts the input's sender constraint on the gateway's word, and a compromised gateway could launder every harvested unexpired token; its residual is strictly larger than `rebind-live-proof`'s.
- **Bearer tokens at hop 1, in any form** (short-lived, single-audience, non-exchangeable, or with session, IP or user-agent checks). Below the floor (RFC 9700 §2.2.1): a stolen token is usable by anyone, and it is the subject token an intermediary would exchange.
- **Refusing every `actor_token`.** No stronger than `client-key`, and it breaks actor-profile conformance and clients that send their own assertion as `actor_token`.
- **DPoP key equal to the long-term client key.** It moves the long-term key into every resource-server request, turns a DPoP key leak into identity compromise, removes instance and task separation, and makes rotation strand live tokens; attestation-based client authentication shares a per-instance key vouched for by a separate attester, not the long-term key.
- **A bearer access token as `actor_token`.** A second, stealable credential.
- **An `actor_token` naming a principal other than the authenticated client.** The actor would not be key-authenticated.
- **A keyless, reusable workload token as actor credential.** It proves possession of nothing.
- **A bare parent-supplied `jkt` for the redeemer key.** A parent could substitute its own key; the signed redeemer key statement replaces it.
- **A public (DPoP-only) agent starting a hand-off.** DPoP is not client authentication.
- **The person delegating to a sub-agent through an unlinked grant.** No cascade, no attenuation, and a consent-phishing channel; replaced by the child grant.
- **Hand-off audience = the token endpoint.** Conflicts with tessera's issuer-only assertion audience, adopted after the 2025 audience-injection disclosure.
- **Revocation by the issued-to client only (RFC 7009 literal).** A parent could not contain a rogue sub-agent.
- **`act.iss` = the global issuer.** Every actor identifier, grant and allow-list would change when the per-realm issuer ships.
- **One namespace per tenant with the baseline as a claim.** Signatures cannot separate baselines of one tenant.
- **Transaction tokens for agent chains.** Bearer tokens for a whole trust domain, not replay resistant; for propagation inside one call graph only.
- **Pass-through, or `client_credentials` for user data.** MCP forbids pass-through, and acting as itself drops the person (the confused deputy of threat row 18).
- **Impersonation tokens, an actor token issued to an intermediary, a client secret for the exchange, the parent's token given to a sub-agent, re-signing every hop, delegation derived from `client_id`.** As in the first design note.

## Existing configuration points that must be bounded

The rule applies to every configuration point, not only the new ones. These exist today and must declare bounded states before the exchange grant can be enabled:

- Access-token lifetimes have no upper bound (`api/TokenService.java:132,406-411`; `api/ClientCredentialsService.java:103-107`).
- `iam.authflow.require-sender-constraint=false` issues unbound Bearer tokens (`props:188`); restricted by decision 6.
- `iam.subject.trust-header=true` trusts `X-Subject-Id` verbatim (`props:204-212`).
- Multi-tenant mode trusts `X-Tenant-Id` verbatim (`rest/tenancy/TenantResolutionFilter.java:84-88`); the per-realm issuer track is the answer.
- Workload issuers may be configured with single use and `jti` off (`rest/token/NimbusClientAssertionVerifier.java:186-196`); excluded from the exchange by decision 5.
- DPoP `proofMaxAge` and `clockSkew` have no upper bound (`rest/config/DpopConfig.java:24-33`).
- `X-Client-Certificate` has no trust switch at all (`rest/token/ClientCertificateThumbprint.java:33`).

## Standards and their status on 2026-10-29

| Specification | Revision | Status | Tessera position |
|---|---|---|---|
| RFC 8693 Token Exchange | January 2020 | Proposed Standard | Adopt, profiled |
| RFC 9449 DPoP | — | Proposed Standard | Adopt; extend to confidential clients, `dpop_jkt`, `dpop_bound_access_tokens` |
| RFC 8705 mTLS | — | Proposed Standard | Adopt once the certificate comes from TLS tessera terminates or an authenticated edge hop |
| RFC 7009, RFC 7662 | — | Proposed Standards | Adopt, extended by lineage and the revocation authority rule |
| RFC 9068, 8414, 9207, 8707, 9728, 9396, 7523 | — | Proposed Standards | Adopt (RFC 8707 at `/authorize` and RFC 9207 metadata are missing today) |
| RFC 9700 OAuth security BCP | January 2025 | Best Current Practice | Followed: sender-constrained tokens (§2.2.1) |
| `draft-mcguinness-oauth-actor-profile` | -01, 2026-10-09 | Individual, no working-group adoption found | Design input: `act.iss`, `may_act` path, self-assertion `actor_token`, presenter rebind (with tessera's live-proof rule) |
| Actor proofs, actor receipts, `draft-mw-oauth-actor-chain` | October 2026 | Individual | Not adopted: one authorization server builds the chain |
| `draft-ietf-oauth-attestation-based-client-auth` | -12, 2026-10-13 | Working-group consensus, waiting for write-up | Basis of the later `attested-instance` states and of attested public agents |
| `draft-ietf-wimse-workload-creds`, `draft-ietf-wimse-wpt` | -02, 2026-07-02; -02, 2026-08-27 | WIMSE working-group documents | Workload credentials with `cnf` qualify under `client-key`; instance attestation later |
| `draft-ietf-wimse-aims` | -00, 2026-09-15 | WIMSE working-group document | Reference for agent-tool patterns |
| `draft-ietf-oauth-identity-chaining` | -17, 2026-07-19 | RFC Editor queue | Adopt on publication for cross-domain chains |
| `draft-ietf-oauth-status-list` | -21, 2026-06-21 | RFC Editor queue | Prototype after publication for recorded tokens |
| `draft-ietf-oauth-transaction-tokens` | -11, 2026-07-30 | Working-group consensus, waiting for write-up | Watch; not an agent-chain mechanism |
| `draft-ietf-oauth-identity-assertion-authz-grant` | -04, 2026-05-21 | Working-group document | After identity chaining is an RFC, for MCP enterprise-managed authorization |
| OAuth 2.1 | -16, 2026-09-03 (MCP pins -13) | Working-group document | Conformance target |
| OpenID SSF 1.0, CAEP 1.0 | — | Final, September 2025 | Watch: no event for token or delegation-grant revocation |
| MCP authorization | 2026-07-28 | Current | Target for hop 1 |
| MCP TypeScript SDK client DPoP | 2.1.0 onwards; 2.4.0 on 2026-10-23 | Released, opt-in | The DPoP-capable hop-1 path |
| MCP SEP 1932 and ext-auth pull request 33 (DPoP for MCP) | Updated 2026-10-21 | Open | Their merge is the revisit trigger for decision 6 |

## Implementation sequence

Sizes: XS a few lines; S up to about a day in one module; M several modules, possibly a migration; L all layers plus a design decision. Prerequisites already scheduled elsewhere: refresh keeping `cnf`, scope and realm (M); realm claims on every mint path (S to emit, S to enforce); RFC 8705 client authentication (L); assertion authentication at `/revoke` and `/introspect` (S).

| Step | Work | Depends on | Size |
|---|---|---|---|
| 1a | Global spent set for `private_key_jwt` assertions; the assertion verifier refuses `typ` `dpop+jwt` | — | S |
| 1b | Shared, capped replay stores for assertions and DPoP proofs, across instances | — | M |
| 1c | Default-closed trust switch for `X-Client-Certificate`, refused in fixed-tenant mode | — | S |
| 1d | Introspection: `cnf`, true `token_type`, no-`exp` inactive, confidential clients only | — | S |
| 1e | Discovery: RFC 9207 flag, `revocation_endpoint`, `introspection_endpoint` | — | XS |
| 1f | Scope allow-list and consent check on the authorization-code grant | — | M |
| 1g | `/token` dispatch through `GrantType`, or an architecture rule against grant-type literals | — | S |
| 1h | Bounded configuration: lifetime caps, DPoP age and skew caps, `require-sender-constraint=false` closed to agent, `act` and subject tokens, startup refusal while the exchange grant is enabled | — | S |
| 1i | Workload issuers usable for the exchange only with `cnf` or enforced single use and `jti`; assertion `jti` spent on refused attempts | 1b | S |
| 2a | `resource` at `/authorize`; single-audience authorization-code tokens | 1f | S to M |
| 2b | `private_key_jwt` on the authorization-code grant; DPoP for confidential clients; `dpop_jkt` at `/authorize`; `dpop_bound_access_tokens` | 1a, 1b | M |
| 2c | Realm registry slice: one opaque id per `(tenant, baseline)`; `Actor` pair type | — | M |
| 2d | Agent and resource registration: the method and grant invariant (domain and database check), resource identifier, "verifies sender constraint", declared downstream set, the three configuration points with their stored values and audit; delegation grants including child grants; consent page; `act` at hop 1 with level stamps | 1f, 1h, 2a, 2c | L |
| 3 | Lineage store, fail-closed introspection of recorded tokens, JWT revocation with the authority rule, client kill switch, caps and quotas, cleanup job | prerequisites, 2c, 2d | M (L with grant withdrawal and the account page) |
| 4 | Single-hop token exchange, off by default: exchange policy, attenuation of scope and resource set through lineage, output bound to the proof that matched the subject token, `exchange.actor-proof` `client-key`, chain monotonicity | 1a to 1i, 2a to 2d, 3 | L |
| 4b | `exchange.actor-proof` `client-attested-key` | 4 | S |
| 5 | Hand-off token with `handoff.redeemer-binding` `client` and `client-and-key` | 4 | M |
| 6 | `exchange.intermediary` `rebind-live-proof`: `subject_token_proof`, `ath` check, path-segment `htu`, fixed 60-second ceiling, forwarded-proof store atomic with lineage | 4 | M |
| 7 | Resource-server guide and conformance vectors: DPoP verification, refusal of `cnf` tokens presented as `Bearer`, gateway `jti` store and `nonce`, minimum levels per tool, the bridge pattern | 4, 5, 6 | M |
| Track | Per-realm issuer (ADR-IAM-003 D3, amended to `(tenant, baseline)`) | 2c | L |
| Later | `attested-instance` and `attested-instance-key` states; Client ID Metadata Documents; Token Status List; identity-assertion grant redemption | drafts or RFCs | M to L each |

Step 4 is not enabled in any deployment until step 3 and assertion authentication at `/revoke` and `/introspect` have shipped. Every new state ships with its refusal tests.

## Not verified

- The RFC 8693 §3 registry entry for `urn:ietf:params:oauth:token-type:jwt` (the string is quoted from actor-profile §6.6.1).
- The RFC 9728 member name for a resource that requires DPoP-bound tokens, and the explicit assertion `typ` value from the RFC 7523 update; both are to be confirmed in the implementing changes.
- Auth0, Curity and Ory token-exchange behaviour (from search extracts), and which community stdio-to-HTTP bridges support DPoP.
- Whether ext-auth pull request 33 changes what an MCP server must do.
- Whether any deployment edge strips `X-Client-Certificate`: no deployment configuration in the repository sets it.
