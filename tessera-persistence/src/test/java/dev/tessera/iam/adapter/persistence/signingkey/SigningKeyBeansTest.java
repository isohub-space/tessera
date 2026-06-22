package dev.tessera.iam.adapter.persistence.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import io.quarkus.runtime.LaunchMode;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The {@link SigningKeyBeans} producer is the fail-closed gate on the envelope master
 * key. These plain (non-{@code @QuarkusTest}) tests drive {@link LaunchMode} directly to
 * prove the gate: in a production run the public development default — and a blank key —
 * are refused at startup, while a real override boots; in dev/test the default is
 * accepted so the service stays runnable without external key management.
 */
@DisplayName("SigningKeyBeans — master key fails closed in production")
class SigningKeyBeansTest {

    private final SigningKeyBeans beans = new SigningKeyBeans();

    // A real (non-default) base64 256-bit master key for the "valid override" cases.
    private static final String REAL_MASTER_KEY =
            Base64.getEncoder().encodeToString(new byte[32]);

    @AfterEach
    void resetLaunchMode() {
        // The producer reads a static volatile; restore the JVM default for other tests.
        LaunchMode.set(LaunchMode.NORMAL);
    }

    @Test
    @DisplayName("production + development-default master key ⇒ refuses to boot")
    void productionWithDevDefaultIsRejected() {
        LaunchMode.set(LaunchMode.NORMAL);
        assertThatThrownBy(() -> beans.envelopeCipher(config(SigningKeyConfig.DEV_DEFAULT_MASTER_KEY)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("iam.keys.master-key");
    }

    @Test
    @DisplayName("production + blank master key ⇒ refuses to boot")
    void productionWithBlankKeyIsRejected() {
        LaunchMode.set(LaunchMode.NORMAL);
        assertThatThrownBy(() -> beans.envelopeCipher(config("  ")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("iam.keys.master-key");
    }

    @Test
    @DisplayName("production + real master-key override ⇒ boots")
    void productionWithRealOverrideBoots() {
        LaunchMode.set(LaunchMode.NORMAL);
        EnvelopeCipher cipher = beans.envelopeCipher(config(REAL_MASTER_KEY));
        assertThat(cipher).isNotNull();
        // It is a usable cipher: seal/open round-trips.
        byte[] secret = "private-key-bytes".getBytes();
        assertThat(cipher.open(cipher.seal(secret))).isEqualTo(secret);
    }

    @Test
    @DisplayName("dev + development-default master key ⇒ boots")
    void devWithDevDefaultBoots() {
        LaunchMode.set(LaunchMode.DEVELOPMENT);
        assertThatCode(() -> beans.envelopeCipher(config(SigningKeyConfig.DEV_DEFAULT_MASTER_KEY)))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("test + development-default master key ⇒ boots")
    void testModeWithDevDefaultBoots() {
        LaunchMode.set(LaunchMode.TEST);
        assertThatCode(() -> beans.envelopeCipher(config(SigningKeyConfig.DEV_DEFAULT_MASTER_KEY)))
                .doesNotThrowAnyException();
    }

    /** A {@link SigningKeyConfig} stub returning a fixed master key. */
    private static SigningKeyConfig config(String masterKey) {
        return new SigningKeyConfig() {
            @Override
            public String masterKey() {
                return masterKey;
            }

            @Override
            public String issuer() {
                return "https://issuer.test.example";
            }

            @Override
            public String maxSigningTtl() {
                return "PT24H";
            }
        };
    }
}
