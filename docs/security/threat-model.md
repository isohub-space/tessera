# Threat model: row-to-test map

Tessera's threat model has 17 rows. For each one, this page names the threat, the defence that answers it, and the test that fails if the defence regresses. A row counts as defended only if a test pins it, so a reviewer can answer "what proves we are not vulnerable to X?" from this page instead of from the source.

Every test named here runs in `mvn verify`. None is disabled. A test qualifies only if it fails when its defence is reverted. That was checked by reverting each defence locally and watching the named test go red; the change that introduced this page records those runs.

Status values:

- **pinned**: a named test fails when the defence is reverted.
- **pinned (current behaviour)**: the test fixes today's behaviour while a decision is open (see [the `iss`/`aud` decision](#the-introspection-iss--aud-decision)).
- **deferred**: the capability the row attacks has not shipped. The row is reopened when that capability ships.

Test locations: `rest` is `tessera-rest/src/test/java/dev/tessera/iam/adapter/rest`, `server` is `tessera-server/src/test/java/dev/tessera/iam/launcher`, `persistence` is `tessera-persistence/src/test/java/dev/tessera/iam/adapter/persistence`, and `domain` is `tessera-domain/src/test/java/dev/tessera/iam/domain`.

## The map

| # | Threat | Defence | Test that fails on regression | Status |
|---|---|---|---|---|
| 1 | Authorization-code replay | Single-use codes: `InMemoryAuthorizationCodeStore.consume` removes and returns the code atomically, and the shared store does the same | `rest/AuthorizationCodeFlowTest.replayedCodeIsRejected`; across nodes, `rest/authcode/AuthorizationCodeStoreIT.concurrentConsumeYieldsExactlyOneGrant` | pinned |
| 2 | Refresh-token reuse | Rotation on every use. Presenting a superseded token burns the whole family (`RefreshReuseDetection`), and the database store applies the decision under a compare-and-swap `UPDATE` | `rest/RefreshTokenFlowTest.replayBurnsFamily`, `domain/refresh/RefreshReuseDetectionTest.previousHashIsReplay`, `persistence/RefreshTokenStoreIT.rotatesAndDetectsReplay` | pinned |
| 3 | CSRF on the authorization response (missing `state`) | `/authorize` refuses a blank `state` with a non-redirectable `400 invalid_request`. The domain `AuthorizationRequest` refuses it too | `rest/AuthorizationCodeFlowTest.missingStateIsRejected`, `domain/authcode/AuthorizationRequestTest.rejectsBlankState` | pinned |
| 4 | Mix-up attack | RFC 9207 `iss` on the authorization response. No authorize-time error is ever redirected, so there is no error redirect that could lack `iss` | `rest/AuthorizationCodeFlowTest.publicClientHappyPath` (asserts `iss`); `unregisteredRedirectUriIsRejected` and `missingPkceChallengeIsRejected` assert that there is no `Location` | pinned |
| 5 | Credential brute force | A failure budget per `(tenant, client)` and per `(tenant, username)` in front of Argon2, plus ingress rate limiting, both built on `TokenBucket` | `rest/ratelimit/CredentialThrottleTest.spentBudgetBypassesDelegate`, `rest/login/LoginThrottleTest.spentBudgetBypassesDelegate`, `rest/ratelimit/RateLimitFilterTest.authorizeThrottled`, `rest/ratelimit/TokenBucketTest.drains` | pinned |
| 6 | Issuer poisoning through the `Host` header | The issuer is server configuration and is never read from the request | `server/DiscoveryEndpointTest.issuerIsConfiguredNotHost` | pinned |
| 7 | Redirect URI tampering | An exact-match allow-list at `/authorize`; at `/token` the code is bound to the exact URI it was issued for | `rest/AuthorizationCodeFlowTest.unregisteredRedirectUriIsRejected`, `redirectUriMismatchIsRejected`, `codeIsBoundToTheExactRedirectUri` (near-misses: trailing slash, extra query, changed case) | pinned |
| 8 | Signature downgrade: `alg:none` and RS/HS algorithm confusion | `JwsAccessTokenIntrospector` accepts only `alg=EdDSA`, checked before any key lookup, and verifies only Ed25519 | `rest/IntrospectForgedTokenTest.algNoneUnsigned`, `algNoneOverValidSignature`, `hs256KeyedWithPublicKey`, `hs256HeaderOverValidSignature`, `rs256AttackerKey`, `rs256HeaderOverValidSignature` | pinned |
| 9 | Token-type confusion (an ID token or other JWT presented as an access token) | The introspector requires `typ=at+jwt` (RFC 9068) | `rest/IntrospectForgedTokenTest.typOtherThanAccessToken` | pinned |
| 10 | JWKS / `kid` injection | A key is selected only by an exact `kid` among the realm's published EdDSA keys. There is no fallback key, and a token without `kid` is refused | `rest/IntrospectForgedTokenTest.unknownKid` | pinned |
| 11 | Cross-tenant replay | Each realm has its own keyset (ADR-IAM-003 D4a), and the introspector trusts only the presenting realm's published keys. Refresh-token lookup is scoped by realm | `rest/IntrospectForgedTokenTest.otherRealmsKid`, `rest/IntrospectFlowTest.crossTenantAccessTokenIsInactive`, `crossTenantRefreshIsInactive`, `rest/RefreshTokenFlowTest.crossTenantIsRejected` | pinned (see note 1) |
| 12 | Signing-key outage: falling back to stale keys or unsigned tokens | No key cache and no fallback. A provider failure fails the request, and readiness reports the signing-key subsystem DOWN | `rest/SigningKeyOutageTest.outageDeniesTokenAndIntrospection`, `server/health/SigningKeyReadinessOutageTest.datasourceFailureIsDown` | pinned |
| 13 | Timing side channel on secret comparison | Constant-time comparison at every site that compares a presented secret with a stored one: PKCE, refresh-token hashes, and client secrets and passwords (password4j's Argon2 check) | `persistence/ConstantTimeComparisonArchTest` (structural; there are no statistical timing tests, by design) | pinned |
| 14 | Audience substitution | Open decision; see [below](#the-introspection-iss--aud-decision) | `rest/IntrospectForgedTokenTest.issAndAudAreNotAssertedByIntrospection` | pinned (current behaviour) |
| 15 | Session fixation | `/login` always mints a fresh server-side session id and never adopts the cookie the client presented | `rest/session/SessionSeamIntegrationTest.loginMintsAFreshSessionIdNeverThePresentedOne` | pinned |
| 16 | `acr` truthfulness (claiming an authentication strength that was not achieved) | Not applicable yet: no token carries `acr`, and step-up / MFA is not wired into login | none | **deferred**: blocked on step-up authentication in the login flow and on `acr` being emitted |
| 17 | SSRF through client-supplied URLs | Not applicable yet: the server never fetches a URL a client supplied (no `jwks_uri`, `request_uri`, `sector_identifier_uri` or dynamic client registration) | none | **deferred**: blocked on the first feature that fetches a client-supplied URL |

Rows 1 to 7 were already pinned. Two of them gained a test at the HTTP level: row 3 was pinned only in the domain model, and row 7 had no near-miss case. Reverting only the `/authorize` check for row 3 is still caught, because the domain model refuses a blank `state` too; reverting both layers fails both tests. Rows 8 to 13 and 15 gained their proving tests with this page. Row 15 moved out of the deferred set because the login and session work made it testable. Row 14 waits on a decision.

**Note 1, cross-tenant replay at the baseline level.** The access-token boundary is the tenant's keyset. ADR-IAM-003 (D4b amendment) records that `DbKeyProviderAdapter.publishedJwks` selects keys by tenant only, so an access token minted for `(tenant, baseline 1)` introspects as active under `(tenant, baseline 2)`. Refresh tokens are already scoped to the full realm (`persistence/RefreshTokenStoreIT.findIsScopedByBaselineNotOnlyTenant`). Closing the access-token half is part of the D4b work, which ADR-IAM-003 gives its own item; it is not claimed here.

**Note 2, what the cross-tenant test double proves.** In `rest/IntrospectForgedTokenTest` the realm keysets come from `FakeKeyProvider`, which mints one key pair per realm. Collapsing it to one shared key pair, the shape ADR-IAM-003 D4a forbids, makes `otherRealmsKid` and `crossTenantAccessTokenIsInactive` fail. In production the partition comes from row-level security on `signing_key`, which the persistence integration tests cover.

## The introspection `iss` / `aud` decision

**Today.** `JwsAccessTokenIntrospector.verify` checks `alg`, `typ`, `kid` and the signature against the realm's published keys. `IntrospectService` then checks `exp`. Neither class compares `iss` or `aud`, and the active response echoes neither. `issAndAudAreNotAssertedByIntrospection` pins this: a token signed by the realm's key with a foreign `iss` and a foreign `aud` is reported active, with neither member in the body.

**What ADR-IAM-003 already says.** D4b says the introspector *should* reject a token whose realm claims or `iss` do not match the realm it is presented in. Its amendments say to compare the full realm, to treat a token without realm claims, `iss` or `exp` as inactive, and to roll out in two phases: emit the claims, wait one access-token lifetime, then enforce. D4b also says it should be split into its own item. ADR-IAM-003 is **Proposed**, not accepted, so `iss` has a proposed answer that is not yet a decision. Until D3 (per-realm issuers) ships, `iss` is the same for every tenant, so comparing it adds no tenant separation. The ADR does not address `aud` at introspection.

**Recorded here as the minimal position for `aud`:** the authorization server does not assert audience at introspection; the resource server does. The reasons:

- RFC 9068 §4 puts the audience check on the resource server, which must check that `aud` names it.
- RFC 7662 §2.2 makes `aud` an optional member of the introspection response, for the protected resource to evaluate.
- The authorization server does not know which resource an introspecting client acts for, because no client-to-resource mapping exists.
- Both access-token mint paths set `aud` to the issuer today, so a server-side audience check would accept every token it issued and prove nothing.

**The gap this leaves, flagged for a decision.** A resource server that relies only on introspection cannot perform its half of the audience check, because the response does not carry `aud`. A resource server that validates the JWT locally can. Three choices are open, and none is made here:

1. Ratify ADR-IAM-003 D4b and schedule the realm-claim and `iss` comparison. That flips `issAndAudAreNotAssertedByIntrospection` for `iss` on purpose.
2. Whether the active introspection response should echo `iss` and `aud` (both optional in RFC 7662), so that a resource server relying on introspection can check audience itself.
3. Whether access tokens should carry per-resource audiences instead of the issuer. That is minting-side work, and it builds on this record rather than deciding it again.
