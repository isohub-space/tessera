package dev.tessera.iam.adapter.rest.session;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the default-closed {@code X-Subject-Id} trust boundary
 * ({@link SessionCookieFilter}/{@link dev.tessera.iam.adapter.rest.tenancy.SubjectHeaders}):
 * with {@code iam.subject.trust-header} at its real production default ({@code false}), a
 * caller-supplied {@code X-Subject-Id} — with no session cookie behind it — must NOT be
 * honoured as an identity by {@code /authorize} or {@code /consent}. Every other test in this
 * module opts into trusted-edge mode module-wide (see the test {@code application.properties})
 * because that is what those tests are actually exercising (OAuth mechanics); this class
 * overrides back to the real default via {@link TestProfile} specifically to test the boundary
 * itself, independent of that blanket opt-in.
 */
@QuarkusTest
@TestProfile(SubjectHeaderTrustBoundaryTest.ClosedByDefault.class)
@DisplayName("X-Subject-Id trust boundary — default-closed: a forged header is not an identity")
class SubjectHeaderTrustBoundaryTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    public static class ClosedByDefault implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            // The real production default — overrides this module's blanket true.
            return Map.of("iam.subject.trust-header", "false");
        }
    }

    @Test
    @DisplayName("a directly-set X-Subject-Id with NO session cookie is refused at /authorize, not honoured")
    void forgedSubjectHeaderRefusedAtAuthorize() {
        String tenant = UUID.randomUUID().toString();

        given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", "attacker-supplied-victim-sub")
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", FakeClientRepository.REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-1")
                .queryParam("nonce", "nonce-1")
                .queryParam("code_challenge", s256(newVerifier()))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize")
                .then()
                // access_denied (no subject), NOT a 302 with an issued code for the forged subject.
                .statusCode(400)
                .body("error", Matchers.equalTo("access_denied"));
    }

    @Test
    @DisplayName("a directly-set X-Subject-Id with NO session cookie is refused at /consent, not honoured")
    void forgedSubjectHeaderRefusedAtConsent() {
        String tenant = UUID.randomUUID().toString();

        given().header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", "attacker-supplied-victim-sub")
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_IDENTITY.value().toString())
                .formParam("scope", "openid")
                .when().post("/consent")
                .then()
                .statusCode(401)
                .body("error", Matchers.equalTo("access_denied"));
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return B64URL.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
