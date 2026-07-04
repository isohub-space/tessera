package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Direct unit test of the redirect-URI allow-list decision in {@link AuthorizationService}. The
 * flow test proves the externally-observable outcome (400, no redirect); this pins the internal
 * security invariant the outcome depends on: a rejected {@code redirect_uri} mints <strong>no
 * code</strong> — the store is never touched — so a future refactor that reorders the checks can't
 * silently issue a code for an unregistered URI.
 */
@DisplayName("AuthorizationService — redirect_uri allow-list enforced before any code is minted")
class AuthorizationServiceTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final String CLIENT_ID = "web-app";
    private static final String REGISTERED = "https://c.example/cb";
    // A structurally valid base64url S256 challenge (43 unpadded chars).
    private static final String CHALLENGE = "a".repeat(43);

    private final AtomicInteger storeCount = new AtomicInteger();

    private AuthorizationService service(Client resolved) {
        ClientRepositoryPort clients =
                (realm, clientId) -> Uni.createFrom().item(CLIENT_ID.equals(clientId) ? resolved : null);
        AuthorizationCodeStorePort codeStore = new AuthorizationCodeStorePort() {
            @Override
            public Uni<Void> store(String code, AuthorizationGrant grant) {
                storeCount.incrementAndGet();
                return Uni.createFrom().voidItem();
            }

            @Override
            public Uni<AuthorizationGrant> consume(RealmKey realm, String code) {
                return Uni.createFrom().nullItem();
            }
        };
        OpaqueIdentifierPort ids = new OpaqueIdentifierPort() {
            @Override
            public String newAuthorizationCode() {
                return "fixed-code";
            }

            @Override
            public String newTokenId() {
                return "fixed-jti";
            }
        };
        return new AuthorizationService(clients, codeStore, ids,
                Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC),
                Duration.ofMinutes(1));
    }

    private static Client publicClient(Set<String> redirectUris) {
        return new PublicClient(
                ClientId.generate(), REALM, Set.<GrantType>of(new AuthorizationCode()), redirectUris);
    }

    private static AuthorizationRequest request(String redirectUri) {
        return new AuthorizationRequest(REALM, CLIENT_ID, redirectUri,
                Set.of("openid"), "state-1", "nonce-1", CodeChallenge.s256(CHALLENGE));
    }

    private AuthorizeResult authorize(Client resolved, String redirectUri) {
        return service(resolved).authorize(request(redirectUri), "sub-1").await().indefinitely();
    }

    @Test
    @DisplayName("a registered redirect_uri issues a code and stores exactly one grant")
    void registeredRedirectUriIssuesCode() {
        AuthorizeResult result = authorize(publicClient(Set.of(REGISTERED)), REGISTERED);
        assertThat(result).isInstanceOf(AuthorizeResult.Issued.class);
        assertThat(storeCount).hasValue(1);
    }

    @Test
    @DisplayName("an unregistered redirect_uri is a non-redirectable INVALID_REQUEST and mints NO code")
    void unregisteredRedirectUriMintsNoCode() {
        AuthorizeResult result =
                authorize(publicClient(Set.of(REGISTERED)), "https://c.example/evil");
        assertThat(result).isInstanceOfSatisfying(AuthorizeResult.Failed.class, failed -> {
            assertThat(failed.error()).isEqualTo(AuthorizationError.INVALID_REQUEST);
            assertThat(failed.redirectable()).isFalse();
        });
        assertThat(storeCount).hasValue(0);
    }

    @Test
    @DisplayName("a client whose registered set is empty can mint no code")
    void emptyAllowListMintsNoCode() {
        AuthorizeResult result = authorize(publicClient(Set.of()), REGISTERED);
        assertThat(result).isInstanceOf(AuthorizeResult.Failed.class);
        assertThat(storeCount).hasValue(0);
    }

    @Test
    @DisplayName("an unknown client mints no code")
    void unknownClientMintsNoCode() {
        AuthorizeResult result = service(null).authorize(request(REGISTERED), "sub-1")
                .await().indefinitely();
        assertThat(result).isInstanceOf(AuthorizeResult.Failed.class);
        assertThat(storeCount).hasValue(0);
    }
}
