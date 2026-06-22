package dev.tessera.iam.adapter.persistence.signingkey;

import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import io.quarkus.runtime.LaunchMode;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.util.Base64;

/**
 * CDI wiring for the signing-key adapter: produces the {@link EnvelopeCipher} from the
 * configured master key.
 *
 * <p>The producer is the fail-closed gate on the master key. The configured default is a
 * well-known, public development value (so the service boots in {@code dev}/{@code test}
 * without external key management). Outside those profiles — i.e. in a normal
 * ({@link LaunchMode#NORMAL}) production run — booting on that default, or on a blank
 * key, is <strong>refused at startup</strong>: it would otherwise wrap every stored
 * private signing key under a key anyone can read. An operator must supply a real
 * {@code iam.keys.master-key} (or, ultimately, delegate wrapping to a KMS/HSM behind the
 * provider port).
 */
@ApplicationScoped
public class SigningKeyBeans {

    /**
     * Builds the envelope cipher from the configured base64 master key, refusing the
     * development default outside dev/test.
     *
     * @throws IllegalStateException in a production run when the master key is absent,
     *         blank, or still the public development default
     */
    @Produces
    @Singleton
    EnvelopeCipher envelopeCipher(SigningKeyConfig config) {
        String configured = config.masterKey();
        requireProductionMasterKey(configured);
        byte[] masterKey = Base64.getDecoder().decode(configured);
        return new EnvelopeCipher(masterKey);
    }

    /**
     * Refuses to boot a production run on a blank master key or the public development
     * default. In {@code dev}/{@code test} the default is accepted so the service stays
     * runnable without external key management.
     */
    private static void requireProductionMasterKey(String configured) {
        if (LaunchMode.current() != LaunchMode.NORMAL) {
            return;
        }
        boolean blank = configured == null || configured.isBlank();
        if (blank || SigningKeyConfig.DEV_DEFAULT_MASTER_KEY.equals(configured)) {
            throw new IllegalStateException(
                    "iam.keys.master-key must be set to a real 256-bit master key outside "
                            + "dev/test; the service refuses to boot on a blank or the "
                            + "well-known development default key. Provide a non-default key "
                            + "(or delegate wrapping to a KMS/HSM).");
        }
    }
}
