package dev.tessera.iam.adapter.persistence.credential;

import static org.assertj.core.api.Assertions.assertThat;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Argon2PasswordCredentialVerifier.check — PHC verification, fail-closed")
class Argon2PasswordCredentialVerifierTest {

    // Small parameters keep the unit test fast; verification derives the real parameters from
    // the stored PHC string, so this only affects the cost of producing the fixture hash.
    private static final Argon2Function FAST = Argon2Function.getInstance(1024, 1, 1, 32, Argon2.ID);

    private static String hash(String password) {
        return Password.hash(password).with(FAST).getResult();
    }

    @Test
    @DisplayName("the correct password verifies against the stored Argon2id hash")
    void correctPasswordAccepted() {
        assertThat(Argon2PasswordCredentialVerifier.check(hash("correct horse battery staple"),
                "correct horse battery staple")).isTrue();
    }

    @Test
    @DisplayName("a wrong password is rejected")
    void wrongPasswordRejected() {
        assertThat(Argon2PasswordCredentialVerifier.check(hash("correct horse battery staple"),
                "not the password")).isFalse();
    }

    @Test
    @DisplayName("a null or blank stored hash (unknown user / no credential) is rejected")
    void noStoredHashRejected() {
        assertThat(Argon2PasswordCredentialVerifier.check(null, "anything")).isFalse();
        assertThat(Argon2PasswordCredentialVerifier.check("   ", "anything")).isFalse();
    }

    @Test
    @DisplayName("an empty presented password is rejected")
    void emptyPresentedRejected() {
        assertThat(Argon2PasswordCredentialVerifier.check(hash("correct horse battery staple"), ""))
                .isFalse();
    }

    @Test
    @DisplayName("a malformed stored hash fails closed rather than throwing")
    void malformedStoredHashFailsClosed() {
        assertThat(Argon2PasswordCredentialVerifier.check("not-a-phc-string", "anything")).isFalse();
    }
}
