# RFC 9700 (OAuth 2.0 Security Best Current Practice) checklist

This checklist covers the requirements of RFC 9700 that fall on an authorization server, as Tessera ships today. Each item is marked as follows:

- **enforced**: the item points at the test that fails if it regresses;
- **not applicable**: the feature the requirement constrains is not offered, and the item names the test that keeps it that way where one exists;
- **deferred**: the requirement applies but is not met yet, and the item says why.

Test locations use the same short prefixes as the [threat-model map](threat-model.md): `rest`, `server`, `persistence` and `domain`.

| RFC 9700 | Requirement (authorization-server side) | Status | Evidence |
|---|---|---|---|
| §2.1, §4.1 | Redirect URIs are compared by exact string match against the registered ones | enforced | `rest/AuthorizationCodeFlowTest.unregisteredRedirectUriIsRejected`, `codeIsBoundToTheExactRedirectUri` |
| §2.1, §4.11.2 | No open redirector: an error is never redirected to an unvalidated URI | enforced | `rest/AuthorizationCodeFlowTest.unregisteredRedirectUriIsRejected`, `unknownClientIsNonRedirectable` (no `Location` on a refused request) |
| §2.1, §4.7 | CSRF protection of the redirect: `state`, with PKCE as the binding | enforced | `rest/AuthorizationCodeFlowTest.missingStateIsRejected`, `missingPkceChallengeIsRejected` |
| §2.1, §4.4 | Mix-up defence: `iss` in the authorization response (RFC 9207) | enforced | `rest/AuthorizationCodeFlowTest.publicClientHappyPath` |
| §2.1.1, §4.5 | PKCE for every client, `S256` only; the code is bound to its challenge | enforced | `rest/AuthorizationCodeFlowTest.missingPkceChallengeIsRejected`, `pkceMismatchIsRejected`; `domain/oidc/OidcCapabilitiesTest.enforcedFlowAndGrants` (no `plain`) |
| §2.1.1, §4.8 | PKCE downgrade: a request without a challenge never yields a code, so no verifier-less redemption exists | enforced | `rest/AuthorizationCodeFlowTest.missingPkceChallengeIsRejected`, `rest/AuthorizationCodeNonceTest.pkceStillMandatoryWithoutNonce` |
| §2.1.1, §4.5 | Authorization codes are single-use and short-lived | enforced | `rest/AuthorizationCodeFlowTest.replayedCodeIsRejected`, `rest/authcode/AuthorizationCodeStoreIT.codeExpires` |
| §2.1.2 | The implicit grant (`response_type=token`) is not offered | not applicable | `domain/oidc/OidcCapabilitiesTest.enforcedFlowAndGrants`, `server/DiscoveryEndpointTest.disabledCapabilitiesNeverAppear` |
| §2.2.1, §4.10 | Access tokens are sender-constrained: DPoP for public clients, mTLS for confidential ones | enforced | `rest/AuthorizationCodeFlowTest.publicClientMissingDpopIsRejected`, `replayedDpopProofIsRejected`, `dpopProofWrongHtuIsRejected`, `confidentialClientMissingCertIsRejected`, `confidentialClientHappyPath` |
| §2.2.2, §4.14 | Refresh tokens for public clients are rotated, with reuse detection | enforced | `rest/RefreshTokenFlowTest.replayBurnsFamily`, `persistence/RefreshTokenStoreIT.rotatesAndDetectsReplay` |
| §2.2.2, §4.14 | Refresh tokens are bound to their client and can be revoked | enforced | `rest/RevokeFlowTest.revokeBurnsFamilyAndIsIdempotent`, `otherClientCannotRevoke` |
| §2.3, §4.10.2 | Access tokens are restricted to the audience of the resource they are for | deferred | Every access token's `aud` is the issuer today. Per-resource audiences are an open decision recorded in the [threat-model map](threat-model.md#the-introspection-iss--aud-decision) |
| §2.4 | The resource owner password credentials grant is not offered | not applicable | `rest/AuthorizationCodeFlowTest.unsupportedGrantTypeIsRejected`, `server/DiscoveryEndpointTest.disabledCapabilitiesNeverAppear` |
| §2.5 | Client authentication: prefer asymmetric methods (mTLS, `private_key_jwt`) | deferred | Confidential clients authenticate with an Argon2id-hashed secret, and the client certificate sender-constrains their tokens but does not yet authenticate the client. `private_key_jwt` and mTLS client authentication are not shipped |
| §2.6 | Authorization server metadata (RFC 8414 / OIDC Discovery) is published and truthful | enforced | `server/DiscoveryEndpointTest.everyAdvertisedEndpointIsServed`, `disabledCapabilitiesNeverAppear` |
| §2.6 | Redirect URIs using the `http` scheme are refused, except loopback redirects for native clients | enforced | Every insert and update of a client checks its redirect URIs: `https` for every client, loopback `http` and reverse-domain private-use schemes for public clients only (RFC 8252 §7), no fragment and no userinfo, anything else refused with `invalid_redirect_uri` (`domain/client/RedirectUriPolicyTest`, `persistence/DbClientRepositoryIT.httpRedirectUriIsRefusedAtRegistration`, `httpRedirectUriIsRefusedAtUpdate`, `publicClientRedirectUris`). A row written to the database directly, outside the application, is not checked |
| §2.6 | CORS is not supported at the authorization endpoint | enforced | With an origin configured, neither a preflight nor a request to `/authorize` gets an `Access-Control-Allow-Origin`, while `/token`, `/introspect`, `/revoke`, discovery and JWKS keep the configured policy (`server/CorsAllowedOriginTest.corsPreflightNeverOpensAuthorize`, `corsRequestNeverOpensAuthorize`, `corsPreflightAllowsListedOriginOnProtocolEndpoints`). With no configured origins, no endpoint answers cross-origin (`server/EdgeSecurityBaselineTest.corsDeniesUnlistedOrigin`) |
| §4.2.2 | The authorization server's pages leak no credential through `Referer` | enforced | `server/EdgeSecurityBaselineTest.securityHeadersPresent` (`Referrer-Policy: no-referrer`) |
| §4.6 | Access-token injection through the front channel | not applicable | No access token is ever returned in the authorization response (`server/DiscoveryEndpointTest.disabledCapabilitiesNeverAppear`) |
| §4.12 | No `307` redirect after a request that carries credentials | enforced | `/authorize` answers `302` (`rest/AuthorizationCodeFlowTest.publicClientHappyPath`); `/login` answers `204`, not a redirect (`rest/login/LoginResourceTest.correctCredentialIssuesCookie`) |
| §4.13 | Behind a reverse proxy, the issuer is not taken from forwarded or `Host` headers | enforced | `server/DiscoveryEndpointTest.issuerIsConfiguredNotHost` |
| §2.6, §4.15 | Clients cannot influence their `client_id` or any claim that could be confused with a resource owner | enforced | Clients are registered by the operator: there is no dynamic client registration. A `client_credentials` token's `sub` and `client_id` are the authenticated client's own, its roles come from its registration, and its realm claims are set last, after the claim pipeline (`rest/ClientCredentialsFlowTest.issuesATokenWithBasicAuthentication`). An end user's `sub` comes only from a verified session (`rest/session/SubjectHeaderTrustBoundaryTest.forgedSubjectHeaderRefusedAtAuthorize`) |
| §4.16 | Clickjacking of the authorization pages | enforced | `server/EdgeSecurityBaselineTest.securityHeadersPresent` (`X-Frame-Options: DENY`) |
| §4.17 | In-browser communication flows (`postMessage`, `response_mode=web_message`) | not applicable | Only `response_mode=query` is served (`server/DiscoveryEndpointTest.disabledCapabilitiesNeverAppear`) |
| §4.9 | Access-token leakage at the resource server | not applicable | A resource-server concern. Tessera's part is sender-constraining (§2.2.1 above) |
