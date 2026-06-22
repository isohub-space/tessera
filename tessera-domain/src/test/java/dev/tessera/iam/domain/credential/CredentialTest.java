package dev.tessera.iam.domain.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("Credential — sealed exhaustiveness + value invariants")
class CredentialTest {

    /**
     * Exhaustive switch over the sealed {@link Credential} hierarchy with no
     * {@code default} branch — a new factor type would break this build.
     */
    private static String kind(Credential credential) {
        return switch (credential) {
            case PasswordHash ignored -> "password";
            case WebAuthnAuthenticator ignored -> "webauthn";
            case TotpSecret ignored -> "totp";
            case RecoveryCode ignored -> "recovery";
        };
    }

    static List<Credential> allCredentials() {
        return List.of(
                new PasswordHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"),
                new WebAuthnAuthenticator(new byte[] {1, 2, 3}, new byte[] {4, 5, 6}, 7L),
                new TotpSecret("JBSWY3DPEHPK3PXP"),
                new RecoveryCode("a1b2c3hashed"));
    }

    @ParameterizedTest
    @MethodSource("allCredentials")
    @DisplayName("exhaustive switch covers every factor kind")
    void exhaustiveSwitchCoversAllKinds(Credential credential) {
        assertThat(kind(credential)).isNotBlank();
    }

    @Test
    @DisplayName("string-based credentials reject blank values")
    void stringCredentialsRejectBlank() {
        assertThatThrownBy(() -> new PasswordHash("  "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TotpSecret(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RecoveryCode(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("WebAuthnAuthenticator defensively copies its byte arrays")
    void webAuthnDefensivelyCopiesBytes() {
        byte[] credentialId = {1, 2, 3};
        byte[] publicKey = {4, 5, 6};
        WebAuthnAuthenticator auth = new WebAuthnAuthenticator(credentialId, publicKey, 0L);

        // Mutating the source arrays must not change the stored credential.
        credentialId[0] = 99;
        publicKey[0] = 99;
        assertThat(auth.credentialId()).containsExactly(1, 2, 3);
        assertThat(auth.publicKeyCose()).containsExactly(4, 5, 6);

        // And the accessor returns a copy, so mutating it does not leak back in.
        auth.credentialId()[0] = 77;
        assertThat(auth.credentialId()).containsExactly(1, 2, 3);
    }

    @Test
    @DisplayName("WebAuthnAuthenticator equality is value-based over array contents")
    void webAuthnValueEquality() {
        WebAuthnAuthenticator a = new WebAuthnAuthenticator(new byte[] {1}, new byte[] {2}, 5L);
        WebAuthnAuthenticator b = new WebAuthnAuthenticator(new byte[] {1}, new byte[] {2}, 5L);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    @DisplayName("WebAuthnAuthenticator rejects empty material and negative counter")
    void webAuthnRejectsInvalid() {
        assertThatThrownBy(() -> new WebAuthnAuthenticator(new byte[0], new byte[] {1}, 0L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new WebAuthnAuthenticator(new byte[] {1}, new byte[0], 0L))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new WebAuthnAuthenticator(new byte[] {1}, new byte[] {1}, -1L))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
