package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.ClientCredentialsUseCase.ClientCredentialsCommand;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.ClaimSourcePort;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authflow.ClaimContext;
import dev.tessera.iam.domain.authflow.Subject;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.token.ClaimSet;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClientCredentialsService — RFC 6749 §4.4 for tenant-bound confidential clients")
class ClientCredentialsServiceTest {

    private static final RealmKey TENANT_A = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final RealmKey TENANT_B = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final String ISSUER = "https://issuer.example";
    private static final String SECRET = "the-secret";
    private static final Instant NOW = Instant.parse("2026-10-21T10:00:00Z");
    private static final Duration TTL = Duration.ofMinutes(5);
    private static final Set<GrantType> CC = Set.of(new ClientCredentials());
    private static final Set<String> AUDIENCES = Set.of("https://orders.example", "https://billing.example");

    private final AtomicReference<ClaimSet> signed = new AtomicReference<>();
    private final AtomicInteger verifierCalls = new AtomicInteger();
    private static final ClientId KEYED = new ClientId(UUID.randomUUID());
    private static final ClientId WORKLOAD = new ClientId(UUID.randomUUID());
    private static final String GOOD_ASSERTION = "a-valid-assertion";
    /** Each key-source lookup, and the trust each assertion verification ran with. */
    private final List<ClientId> keyLookups = new ArrayList<>();
    private final List<AssertionTrust> assertionChecks = new ArrayList<>();

    /** Every client lives in tenant A only: the registry is realm-scoped like the real one. */
    private Map<String, Client> clientsOfTenantA() {
        return Map.of(
                "service", confidential("service", CC, new LinkedHashSet<>(List.of("orders.read", "orders.write")), AUDIENCES,
                        ClientAuthMethod.CLIENT_SECRET),
                "code-only", confidential("code-only", Set.of(new AuthorizationCode()), Set.of("orders.read"),
                        AUDIENCES, ClientAuthMethod.CLIENT_SECRET),
                "no-audience", confidential("no-audience", CC, Set.of("orders.read"), Set.of(),
                        ClientAuthMethod.CLIENT_SECRET),
                "mtls-auth", confidential("mtls-auth", CC, Set.of("orders.read"), AUDIENCES, ClientAuthMethod.MTLS),
                "spa", new PublicClient(new ClientId(UUID.randomUUID()), TENANT_A, CC, Set.of()),
                "profile-service", confidential("profile-service", CC, Set.of("profile"), AUDIENCES,
                        ClientAuthMethod.CLIENT_SECRET),
                "workload", new ConfidentialClient(WORKLOAD, TENANT_A, CC, ClientAuthMethod.WORKLOAD_IDENTITY, Set.of(),
                        Set.of("orders.read"), AUDIENCES, List.of()),
                "keyed", new ConfidentialClient(KEYED, TENANT_A, CC, ClientAuthMethod.PRIVATE_KEY_JWT, Set.of(),
                        Set.of("orders.read"), AUDIENCES, List.of()));
    }

    private static ConfidentialClient confidential(
            String key, Set<GrantType> grants, Set<String> scopes, Set<String> audiences, ClientAuthMethod auth) {
        return new ConfidentialClient(new ClientId(UUID.randomUUID()), TENANT_A, grants,
                auth, Set.of(), scopes, audiences, List.of("ops", "reader"));
    }

    private ClientRepositoryPort registry() {
        Map<String, Client> registry = clientsOfTenantA();
        return (realm, clientId) -> Uni.createFrom().item(realm.equals(TENANT_A) ? registry.get(clientId) : null);
    }

    private ClientCredentialsService service(boolean requireSenderConstraint) {
        return service(requireSenderConstraint, new RegisteredClientClaimSource(registry()));
    }

    private ClientCredentialsService service(boolean requireSenderConstraint, ClaimSourcePort claimSource) {
        ClientRepositoryPort clients = registry();
        // Like the Argon2 verifier: true only for a known confidential client and its secret.
        ClientSecretVerifierPort secrets = (realm, id, secret) -> {
            verifierCalls.incrementAndGet();
            return Uni.createFrom().item(!ClientSecretVerifierPort.isReserved(id.value()) && SECRET.equals(secret));
        };
        TokenSignerPort signer = (realm, typ, claims) -> {
            signed.set(claims);
            return Uni.createFrom().item("signed." + typ);
        };
        OpaqueIdentifierPort ids = new OpaqueIdentifierPort() {
            @Override
            public String newAuthorizationCode() {
                return "code";
            }

            @Override
            public String newTokenId() {
                return "jti-1";
            }

            @Override
            public String newRefreshToken() {
                return "refresh";
            }

            @Override
            public UUID newFamilyId() {
                return UUID.randomUUID();
            }
        };
        // Like the key source and the JOSE verifier: only the keyed client has a trust, and only the
        // valid assertion verifies against it.
        ClientKeySourcePort keys = (realm, id) -> {
            keyLookups.add(id);
            return Uni.createFrom().item(KEYED.equals(id) ? new AssertionTrust("keyed", "keyed", "{\"keys\":[]}")
                    : WORKLOAD.equals(id) ? AssertionTrust.ofIssuer("https://platform.example", "sa-1") : null);
        };
        ClientAssertionVerifierPort assertions = (realm, trust, assertion) -> {
            assertionChecks.add(trust);
            return Uni.createFrom().item(trust != null && GOOD_ASSERTION.equals(assertion));
        };
        return new ClientCredentialsService(clients, secrets, keys, assertions, claimSource, signer, ids,
                Clock.fixed(NOW, ZoneOffset.UTC), ISSUER, TTL, requireSenderConstraint);
    }

    private TokenResult issue(String clientId, String secret, String scope, List<String> resources) {
        return issue(TENANT_A, clientId, secret, scope, resources, null, false);
    }

    private TokenResult issue(RealmKey realm, String clientId, String secret, String scope, List<String> resources,
            String cert, boolean requireSenderConstraint) {
        return service(requireSenderConstraint)
                .issue(new ClientCredentialsCommand(realm, clientId, secret, scope, resources, cert))
                .await().indefinitely();
    }

    private static void assertFailed(TokenResult result, AuthorizationError error) {
        assertThat(result).isInstanceOfSatisfying(TokenResult.Failed.class,
                failed -> assertThat(failed.error()).isEqualTo(error));
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("a registered client gets a token for itself: sub = client_id, its scopes, audiences, roles, tenant")
    void issuesATokenForTheClient() {
        TokenResult result = issue("service", SECRET, null, List.of());

        assertThat(result).isInstanceOfSatisfying(TokenResult.Issued.class, issued -> {
            assertThat(issued.tokenType()).isEqualTo("Bearer");
            assertThat(issued.expiresInSecs()).isEqualTo(TTL.toSeconds());
            assertThat(issued.scope()).isEqualTo("orders.read orders.write");
            assertThat(issued.refreshToken()).isNull();
            assertThat(issued.idToken()).isNull();
        });
        Map<String, Object> claims = signed.get().claims();
        assertThat(claims)
                .containsEntry("iss", ISSUER)
                .containsEntry("sub", "service")
                .containsEntry("client_id", "service")
                .containsEntry("scope", "orders.read orders.write")
                .containsEntry("roles", List.of("ops", "reader"))
                .containsEntry("realm_tenant", TENANT_A.tenant().value().toString())
                .containsEntry("realm_baseline", TENANT_A.baseline().value().toString())
                .containsEntry("iat", NOW.getEpochSecond())
                .containsEntry("exp", NOW.plus(TTL).getEpochSecond())
                .doesNotContainKey("cnf");
        assertThat((List<Object>) claims.get("aud")).containsExactlyInAnyOrderElementsOf(List.copyOf(AUDIENCES))
                .doesNotContain(ISSUER);
    }

    @Test
    @DisplayName("requested scopes narrow the grant; a scope outside the registration is invalid_scope")
    void scopesNarrowButNeverWiden() {
        assertThat(issue("service", SECRET, "orders.read", List.of()))
                .isInstanceOfSatisfying(TokenResult.Issued.class, i -> assertThat(i.scope()).isEqualTo("orders.read"));
        assertFailed(issue("service", SECRET, "orders.read admin", List.of()), AuthorizationError.INVALID_SCOPE);
    }

    @Test
    @DisplayName("a resource indicator narrows aud to it; one outside the registration is invalid_target (RFC 8707)")
    void resourceNarrowsButNeverWidens() {
        assertThat(issue("service", SECRET, null, List.of("https://orders.example")))
                .isInstanceOf(TokenResult.Issued.class);
        assertThat(signed.get().claims()).containsEntry("aud", "https://orders.example");
        assertFailed(issue("service", SECRET, null, List.of("https://orders.example", "https://other.example")),
                AuthorizationError.INVALID_TARGET);
        assertFailed(issue("service", SECRET, null, List.of(ISSUER)), AuthorizationError.INVALID_TARGET);
    }

    @Test
    @DisplayName("a client with no registered audience is refused: aud is never the issuer")
    void clientWithoutAudienceIsRefused() {
        assertFailed(issue("no-audience", SECRET, null, List.of()), AuthorizationError.UNAUTHORIZED_CLIENT);
    }

    @Test
    @DisplayName("unknown client, wrong or missing secret, and a public client are all invalid_client")
    void clientAuthenticationFailuresLookAlike() {
        assertFailed(issue("nobody", SECRET, null, List.of()), AuthorizationError.INVALID_CLIENT);
        assertFailed(issue("service", "wrong", null, List.of()), AuthorizationError.INVALID_CLIENT);
        assertFailed(issue("service", null, null, List.of()), AuthorizationError.INVALID_CLIENT);
        assertFailed(issue("spa", SECRET, null, List.of()), AuthorizationError.INVALID_CLIENT);
        assertThat(signed.get()).isNull();
    }

    @Test
    @DisplayName("a client not registered for the grant is unauthorized_client")
    void grantMustBeRegistered() {
        assertFailed(issue("code-only", SECRET, null, List.of()), AuthorizationError.UNAUTHORIZED_CLIENT);
    }

    @Test
    @DisplayName("a client of tenant A cannot obtain a token in tenant B; it still can in A")
    void clientIsBoundToItsTenant() {
        assertFailed(issue(TENANT_B, "service", SECRET, null, List.of(), null, false),
                AuthorizationError.INVALID_CLIENT);
        assertThat(signed.get()).isNull();
        assertThat(issue(TENANT_A, "service", SECRET, null, List.of(), null, false))
                .isInstanceOf(TokenResult.Issued.class);
    }

    @Test
    @DisplayName("a presented certificate binds the token; without one it is refused when sender-constraint is required")
    void senderConstraintFollowsTheAuthorizationCodePath() {
        assertThat(issue(TENANT_A, "service", SECRET, null, List.of(), "thumb", true))
                .isInstanceOf(TokenResult.Issued.class);
        assertThat(signed.get().claims()).containsEntry("cnf", Map.of("x5t#S256", "thumb"));
        assertFailed(issue(TENANT_A, "service", SECRET, null, List.of(), null, true),
                AuthorizationError.INVALID_REQUEST);
        assertFailed(issue(TENANT_A, "mtls-auth", SECRET, null, List.of(), null, false),
                AuthorizationError.INVALID_REQUEST);
    }

    @Test
    @DisplayName("the secret verifier runs exactly once on every outcome, so a client_id's existence is not timed")
    void verifierRunsOnceOnEveryPath() {
        Map<String, Runnable> paths = new java.util.LinkedHashMap<>();
        paths.put("unknown client", () -> issue("nobody", SECRET, null, List.of()));
        paths.put("other tenant", () -> issue(TENANT_B, "service", SECRET, null, List.of(), null, false));
        paths.put("public client", () -> issue("spa", SECRET, null, List.of()));
        paths.put("missing secret", () -> issue("service", null, null, List.of()));
        paths.put("wrong secret", () -> issue("service", "wrong", null, List.of()));
        paths.put("not registered for the grant", () -> issue("code-only", SECRET, null, List.of()));
        paths.put("invalid scope", () -> issue("service", SECRET, "admin", List.of()));
        paths.put("success", () -> issue("service", SECRET, null, List.of()));
        paths.forEach((path, request) -> {
            verifierCalls.set(0);
            request.run();
            assertThat(verifierCalls.get()).as(path).isEqualTo(1);
        });
    }

    private TokenResult issueWithAssertion(String clientId, String assertion) {
        return service(false)
                .issue(new ClientCredentialsCommand(TENANT_A, clientId, null, assertion, null, List.of(), null))
                .await().indefinitely();
    }

    @Test
    @DisplayName("a private_key_jwt client authenticates with an assertion and gets a token for itself")
    void assertionAuthenticatesAKeyedClient() {
        assertThat(issueWithAssertion("keyed", GOOD_ASSERTION)).isInstanceOf(TokenResult.Issued.class);
        assertThat(signed.get().claims()).containsEntry("sub", "keyed").containsEntry("client_id", "keyed");
        assertThat(keyLookups).containsExactly(KEYED);
        assertThat(verifierCalls).hasValue(0);
    }

    @Test
    @DisplayName("a workload-identity client authenticates with its issuer's token, never with a secret")
    void workloadIdentityClientUsesTheAssertionPath() {
        assertThat(issueWithAssertion("workload", GOOD_ASSERTION)).isInstanceOf(TokenResult.Issued.class);
        assertThat(keyLookups).containsExactly(WORKLOAD);
        assertThat(assertionChecks).containsExactly(AssertionTrust.ofIssuer("https://platform.example", "sa-1"));
        assertFailed(issue("workload", SECRET, null, List.of()), AuthorizationError.INVALID_CLIENT);
    }

    @Test
    @DisplayName("method mismatch: a secret client's assertion and a keyed client's secret are invalid_client")
    void eachClientAuthenticatesOnlyWithItsMethod() {
        assertFailed(issueWithAssertion("service", GOOD_ASSERTION), AuthorizationError.INVALID_CLIENT);
        assertFailed(issue("keyed", SECRET, null, List.of()), AuthorizationError.INVALID_CLIENT);
        assertThat(signed.get()).isNull();
    }

    @Test
    @DisplayName("the key source and the assertion verifier run once on every outcome, with no trust unless keyed")
    void assertionPathRunsTheSameStepsOnEveryOutcome() {
        Map<String, String> clientsAndAssertions = new java.util.LinkedHashMap<>();
        clientsAndAssertions.put("nobody", GOOD_ASSERTION);
        clientsAndAssertions.put("spa", GOOD_ASSERTION);
        clientsAndAssertions.put("service", GOOD_ASSERTION);
        clientsAndAssertions.put("keyed", "a-bad-assertion");
        clientsAndAssertions.forEach((client, assertion) -> {
            keyLookups.clear();
            assertionChecks.clear();
            assertFailed(issueWithAssertion(client, assertion), AuthorizationError.INVALID_CLIENT);
            assertThat(keyLookups).as(client).hasSize(1);
            assertThat(assertionChecks).as(client).hasSize(1);
            assertThat(assertionChecks.get(0) == null).as(client).isEqualTo(!"keyed".equals(client));
        });
        assertThat(keyLookups.get(0)).isEqualTo(KEYED);
    }

    @Test
    @DisplayName("realm claims from the claim pipeline are overwritten by the request's realm")
    void realmClaimsCannotBeSetUpstream() {
        // A claim source answering for another realm, with profile granted, makes the contributor
        // write that realm's realm_tenant; the mint path must overwrite it.
        ClaimSourcePort foreign = (subject, realm, scopes) ->
                Uni.createFrom().item(new ClaimContext(new Subject(subject.subjectId(), TENANT_B), TENANT_B,
                        List.of(), scopes));
        TokenResult result = service(false, foreign)
                .issue(new ClientCredentialsCommand(TENANT_A, "profile-service", SECRET, "profile", List.of(), null))
                .await().indefinitely();

        assertThat(result).isInstanceOf(TokenResult.Issued.class);
        assertThat(signed.get().claims())
                .containsEntry("realm_tenant", TENANT_A.tenant().value().toString())
                .containsEntry("realm_baseline", TENANT_A.baseline().value().toString());
    }
}
