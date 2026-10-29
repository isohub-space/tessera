# Agent delegation profile: token exchange, multi-hop `act` chains, attenuation, no impersonation

| Field | Value |
|---|---|
| Date | 2026-10-29 |
| Status | Recommendation from a research spike. It is not a decision; the first follow-up below turns it into one. |
| Question | How does an agent act on behalf of a person, or of another agent, with a scoped, time-limited delegated token that proves the whole chain, never a copied credential and never impersonation? |
| Builds on | [Agentic IAM landscape, October 2026](agentic-iam-landscape-2026-10.md) (sources and maturity ratings), [ADR-IAM-004](../adr/ADR-IAM-004-end-user-session-and-consent.md) (consent), [ADR-IAM-006](../adr/ADR-IAM-006-standalone-provider-for-many-sites-and-agents.md) (agents are first-class clients), [threat model](../security/threat-model.md) rows 18 to 25 |

## Background

Tessera issues tokens to agents today only as clients acting for themselves (`client_credentials`) or as ordinary clients acting for a signed-in person (authorization code). Neither tells a resource server that an agent is acting, or for whom, and an agent cannot pass a narrower right on to a sub-agent without handing over its own token. The token exchange grant (RFC 8693) is the standard answer, and the `GrantType` sealed interface excludes it at compile time on purpose. This note recommends the profile under which that exclusion is lifted.

Primary sources (all read 2026-10-28, see the landscape note for status and dates): RFC 8693, RFC 9449, RFC 8705, RFC 8707, RFC 9068, RFC 7009, RFC 9396, the MCP authorization specification of 2026-07-28, and the individual draft `draft-mcguinness-oauth-actor-profile-01` (9 October 2026), which is the closest published profile of `act` for agents. This profile uses that draft as design input, not as a normative dependency.

## The profile in three lines

1. **Delegation only.** Every token tessera mints for an agent acting for someone carries the person in `sub` and the acting chain in nested `act`, built by tessera alone. The actor is the client that authenticates the exchange request, and no grant ever produces a token without `act`.
2. **Attenuation at every hop.** Scope and audience only shrink, expiry never extends, depth is capped, an actor cannot reappear in its own chain, and an exchanged token gets no refresh token.
3. **Bound and revocable.** Every delegated token is bound to the key of the hop that presents it (DPoP or mTLS). Tessera records each token's parent, so withdrawing a grant or revoking a link deactivates everything issued below it.

## Roles and tokens

- **Subject**: the person (or, for an autonomous chain, the root client) in whose name the work is done. Always the top-level `sub`.
- **Actor**: a client registered with tessera as an agent, a sub-agent, or an intermediary such as an MCP gateway acting as a resource server that calls further APIs.
- **Delegation grant**: tessera's server-side record of a subject's consent to an actor (below).
- **Delegated access token**: an RFC 9068 access token with `act`, a single audience, and `cnf`.
- **Hand-off token**: a short-lived, single-use token that lets one actor pass a narrower right to a named next actor. It is redeemable only at tessera's token endpoint.

A delegated access token for a person, an agent and a sub-agent calling one API:

```json
{
  "iss": "https://id.example",
  "sub": "user-7f3a",
  "aud": "https://api.example/mcp",
  "scope": "files:read",
  "exp": 1793260800,
  "jti": "b1e9…",
  "client_id": "sub-agent-b",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "act": {
    "iss": "https://id.example",
    "sub": "sub-agent-b",
    "act": { "iss": "https://id.example", "sub": "agent-a" }
  }
}
```

`act.sub` is the client identifier, and `act.iss` is tessera's issuer, so an actor is named by the pair as the actor-profile draft requires. The outermost `act` is the current presenter and matches `client_id`. Inner `act` objects are a record of who acted earlier: RFC 8693 §4.1 makes them "informational only", and this profile keeps them out of access decisions.

## D1: the actor is the authenticated client

The open question was whether the actor is shown by an `actor_token` issued to the intermediary, or by the intermediary's own client authentication. **Recommendation: client authentication is the actor.**

- The actor of an exchange is the client that authenticates the request at `/token`, by mTLS, `private_key_jwt` or workload identity. A client secret is not accepted for the exchange grant.
- An `actor_token` is optional. When present it must be a credential whose `sub` is that same authenticated client: a JWT client assertion or a workload credential, never a token carrying `act`. An `actor_token` that names any other party is refused with `invalid_request`. Tessera never issues a separate "actor token" to an intermediary.
- Authenticating as a client is never by itself a reason to act for someone (the actor-profile draft says the same). The right to act comes from a delegation basis (D4).

**Why.** One credential per actor, and the key that authenticates the exchange is the key the output is bound to. An `actor_token` for another party would let a client present a credential it was lent, which is the copied-credential case this profile exists to rule out. It also gives an MCP gateway acting as a resource server a simple shape: it is a confidential client with mTLS or `private_key_jwt`, and its client authentication makes it the next actor when it calls a further API.

## D2: how a chain is built

Every exchange request uses `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` and DPoP or mTLS on the request.

**Hop 1, person to agent.** The agent is an ordinary client of the authorization-code flow, registered as an agent. The consent screen names the agent and the resources, scopes, re-delegation and expiry it asks for (D4). The access token it receives carries `act: {iss, sub: <agent>}`, so a resource server never has to infer delegation from `client_id`. Depth is 1.

**Exchange for another resource.** An actor that holds a delegated token and needs a token for a different resource (inside the grant) exchanges with `subject_token=<its token>`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`, and `resource=<target>`. It proves possession of the subject token by signing the request with the same DPoP key, or by presenting the same client certificate. The chain and depth stay the same; scope and audience may only narrow.

**Hand-off to a sub-agent (two steps).** A sub-agent cannot prove possession of its parent's token, and must never receive it.

1. The parent exchanges its token, proving possession, with `requested_token_type` set to a tessera hand-off type and the next actor's client identifier named as the audience. Tessera issues a hand-off token: `aud` is tessera's own token endpoint, `may_act` names the next actor (RFC 8693 §4.4), the scope requested (a subset), and a lifetime of at most 60 seconds. It records the parent link.
2. The sub-agent exchanges the hand-off token, authenticating as itself and proving its own key. Tessera checks that `may_act` names the authenticated client, that the hand-off token is unused (its `jti` is consumed atomically, like an authorization code), and then issues a delegated access token with the sub-agent as the new outermost `act`, bound to the sub-agent's key. Depth is the parent's plus one.

**Inputs tessera refuses.** A subject token that tessera did not issue, or that was issued in another realm (tenant and baseline); an inactive, expired or revoked subject token; a subject token without `typ=at+jwt` or `act` where one is required; and any inbound `act` it did not build itself. Cross-domain chains (a subject token from another issuer) wait for identity chaining (landscape note) and are out of this profile.

## D3: attenuation rules, enforced by tessera at every hop

| Rule | Check | Error |
|---|---|---|
| Scope only narrows | requested scope ⊆ subject token's scope, by exact string; no scope hierarchy is expanded | `invalid_scope` |
| Audience only narrows | requested resource ∈ the delegation grant's resources ∩ the actor's registered audiences; one audience per token (RFC 8707) | `invalid_target` |
| Fine-grained rights only narrow | `authorization_details` (RFC 9396) accepted only when every entry equals or is an exact subset of an entry in the subject token; otherwise refused | `invalid_authorization_details` |
| Expiry never extends | `exp` ≤ the subject token's `exp` and ≤ the grant's expiry; default lifetime 5 minutes for depth ≥ 2 | issued shorter, never longer |
| Depth is capped | new depth ≤ min(deployment ceiling, the grant's limit); ceiling configurable, at most 4 (the draft's interoperable minimum for multi-hop), default 2 (person, agent, sub-agent) | `invalid_request` |
| No cycles | the new actor must not already appear in the chain | `invalid_request` |
| No refresh | an exchanged token never comes with a refresh token; the actor exchanges again from its upstream token | — |
| Delegation basis required | D4 | `access_denied` |

Every refusal is the same shape at the token endpoint, as today: the client learns which rule it broke only through the error code, never the content of the subject token.

## D4: consent

**Standing grant (default).** At hop 1 the person approves a delegation grant for one agent. It extends ADR-IAM-004's `(user, client)` consent with the dimensions delegation needs: the resources, the scopes, the sub-agents it may hand off to (an explicit list of client identifiers in the first version; "any agent" is not offered), the maximum depth, and an expiry (default 30 days, never open-ended). The consent screen names the agent and every listed sub-agent. Changing any dimension asks again.

**Per-task approval.** A resource server or operator can mark scopes as needing per-task approval. A standing grant never covers them. The agent asks for each task with RFC 9396 `authorization_details` through the authorization-code flow; a back-channel request (CIBA) for agents running without a browser is a later step (the landscape note rates it watch). Approval for one task cannot be widened by exchange (D3).

**Withdrawal.** The person withdraws a grant from the account page, or through the revocation endpoint for one token. Withdrawing a grant refuses new exchanges for that `(subject, actor)` pair at once and deactivates every token issued under it (D6).

**Autonomous chains.** An agent acting for itself (`client_credentials`) is the subject. Its tokens carry no `act`. It may hand off only under an operator-configured delegation grant with the same dimensions.

## D5: what a resource server checks

A resource server, including an MCP gateway acting as a resource server, accepts a delegated token only when all of the following hold.

1. **Token validity (RFC 9068).** `alg` is the issuer's (EdDSA), `typ` is `at+jwt`, `kid` is a published key, the signature verifies, `iss` equals the configured issuer byte for byte, `exp` has not passed.
2. **Audience.** `aud` is its own canonical URI, the one it publishes in its RFC 9728 metadata. MCP makes this a MUST.
3. **Proof of possession against the top-level `cnf`.** A DPoP proof for `cnf.jkt` (method, URI, access-token hash, freshness and replay), or the mTLS client certificate for `cnf["x5t#S256"]`. A token with `act` but without `cnf` is refused: tessera never issues one.
4. **Chain shape.** Depth ≤ the resource server's own limit, and every `act` object has `iss` and `sub`.
5. **The decision uses two principals.** It authorizes the pair (`sub`, outermost `act.sub`): the scope must cover the operation, and the current actor must be allowed to perform it for that subject (an allow-list per tool or route). It never authorizes on `sub` alone when `act` is present. Inner actors are written to the audit record, not used in the decision.
6. **Tenant from the token.** The tenant or realm it acts in comes from the signed token's claims, never from a request header.
7. **No pass-through.** To call a further API it exchanges as the next actor (D1, D2) and never forwards the token it received, as MCP requires.
8. **Errors.** Signature, issuer, audience, time, binding or depth failures: `401` with `invalid_token`. The actor not being allowed: `403`. Missing scope: `403` with `insufficient_scope` and the scopes needed, as MCP describes.
9. **When revocation matters.** An operation whose effect cannot be undone introspects the token instead of trusting the JWT alone, so a withdrawal takes effect at once (D6). This needs the introspection response to carry `act`, `aud` and `iss`, which is option 2 of the open `iss`/`aud` decision in the threat model.

## D6: revocation

- Tessera records, for every delegated token and hand-off token it issues, its `jti`, its parent `jti` and its delegation grant. Refresh-token families already work this way.
- **Withdrawing a grant** refuses new exchanges for that `(subject, actor)` pair, and every token issued under the grant introspects as inactive.
- **Revoking one token** (RFC 7009) deactivates it and every token issued below it. Tokens above it in the chain are unaffected.
- **A resource server that validates the JWT locally** sees a revocation only when the token expires. That is why delegated tokens are short-lived (D3) and irreversible operations introspect (D5).
- Revocation checks are never skipped for any depth.

## Rejected alternatives

- **Impersonation tokens (no `act`).** The resource server cannot tell that an agent acted, which is the problem this profile solves.
- **An `actor_token` issued to an intermediary.** A second credential to steal, and a client could present a credential that is not its own (D1).
- **Passing the parent's token to the sub-agent.** This is the copied credential, and the sub-agent cannot prove possession of it anyway.
- **Transaction tokens for agent chains.** They are for use inside one trust domain, and the draft states they are not sender-constrained or replay resistant.
- **Re-signing every hop, with the chain carried in an HTTP field** (as in the attenuated-delegation draft). This is not an OAuth token format, it defines no revocation, and resource servers would need a second verifier.
- **Deriving delegation from `client_id` or `azp`.** A token issued to a client says nothing about whose authority it uses.
- **"Any agent" re-delegation in standing grants.** It turns consent to one agent into consent to an open set.

## Open items

- How a hand-off token's `requested_token_type` is named: a tessera URN, or an existing token type with a hand-off profile. Interoperability argues for following the actor-profile draft if it is adopted by the working group.
- Whether `act` objects carry a `sub_profile` (the draft's entity type), so that a resource server can tell an agent from a person or service.
- The consent page's design, and the account page that lists and withdraws grants.
- The `actor_unauthorized` error code: the actor-profile draft defines it, but it is not registered. Until it is, a `403` without that code.

## Follow-up work

This table is superseded by the implementation sequence of the [agent delegation decisions](agent-delegation-decisions.md).

| # | Title | Scope | Size |
|---|---|---|---|
| 1 | Decision record: the token exchange grant and the agent delegation profile | Turn D1 to D6 into an ADR. Lift the compile-time exclusion for a delegation-only exchange grant. Record the actor model and the attenuation rules | S |
| 2 | Token exchange grant, single hop | `grant_type=token-exchange` for tessera-issued subject tokens. The actor comes from client authentication. `act` is emitted, the D3 rules are enforced, the output is bound by DPoP or mTLS, and no refresh token is issued. Pins threat rows 18 to 21, 23 and 24 | L |
| 3 | Delegated authorization-code tokens and delegation grants | Clients registered as agents. `act` at hop 1. The consent schema grows by resource, sub-agent list, depth and expiry, and the consent page names the agent | M |
| 4 | Hand-off to a sub-agent | The hand-off token (`may_act`, single use, `aud` is the token endpoint). Depth cap and cycle check. Pins row 22 | M |
| 5 | Delegation lineage and cascading revocation | Parent links for issued tokens. Withdrawal and RFC 7009 cascade. Introspection reports `act`, `aud` and `iss`. Pins row 25 | M |
| 6 | Resource indicators at `/authorize` | RFC 8707 `resource` on the authorization-code path; `aud` is the resource instead of the issuer. A prerequisite for steps 2 and 3, and an MCP MUST | S |
| 7 | DPoP for confidential clients | Accept DPoP on `client_credentials` and token exchange, so an agent without a client certificate still gets a bound token | S |
| 8 | Resource-server validation guide and conformance tests | D5 as a checklist with test vectors, for an MCP gateway acting as a resource server and for any API | M |
