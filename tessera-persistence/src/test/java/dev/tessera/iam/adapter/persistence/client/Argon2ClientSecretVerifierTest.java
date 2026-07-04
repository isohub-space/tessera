package dev.tessera.iam.adapter.persistence.client;

import static org.assertj.core.api.Assertions.assertThat;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Argon2ClientSecretVerifier.check — PHC verification, fail-closed")
class Argon2ClientSecretVerifierTest {

    // Small parameters keep the unit test fast; verification derives the real parameters from
    // the stored PHC string, so this only affects the cost of producing the fixture hash.
    private static final Argon2Function FAST = Argon2Function.getInstance(1024, 1, 1, 32, Argon2.ID);

    private static String hash(String secret) {
        return Password.hash(secret).with(FAST).getResult();
    }

    @Test
    @DisplayName("the correct secret verifies against the stored Argon2id hash")
    void correctSecretAccepted() {
        assertThat(Argon2ClientSecretVerifier.check(hash("s3cr3t-value"), "s3cr3t-value")).isTrue();
    }

    @Test
    @DisplayName("a wrong secret is rejected")
    void wrongSecretRejected() {
        assertThat(Argon2ClientSecretVerifier.check(hash("s3cr3t-value"), "not-the-secret")).isFalse();
    }

    @Test
    @DisplayName("a null or blank stored hash (unknown client / no secret) is rejected")
    void noStoredSecretRejected() {
        assertThat(Argon2ClientSecretVerifier.check(null, "anything")).isFalse();
        assertThat(Argon2ClientSecretVerifier.check("   ", "anything")).isFalse();
    }

    @Test
    @DisplayName("a null presented secret is rejected")
    void nullPresentedRejected() {
        assertThat(Argon2ClientSecretVerifier.check(hash("s3cr3t-value"), null)).isFalse();
    }

    @Test
    @DisplayName("a malformed stored hash fails closed rather than throwing")
    void malformedStoredHashFailsClosed() {
        assertThat(Argon2ClientSecretVerifier.check("not-a-phc-string", "anything")).isFalse();
    }
}
