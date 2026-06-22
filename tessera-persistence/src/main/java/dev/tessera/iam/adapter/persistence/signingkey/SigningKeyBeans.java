package dev.tessera.iam.adapter.persistence.signingkey;

import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Singleton;
import java.util.Base64;

/**
 * CDI wiring for the signing-key adapter: produces the {@link EnvelopeCipher} from the
 * configured master key.
 */
@ApplicationScoped
public class SigningKeyBeans {

    /**
     * Builds the envelope cipher from the configured base64 master key.
     *
     * <p>In a production deployment this dev master key is unused — wrapping is delegated
     * to a KMS/HSM behind the provider port.
     */
    @Produces
    @Singleton
    EnvelopeCipher envelopeCipher(SigningKeyConfig config) {
        byte[] masterKey = Base64.getDecoder().decode(config.masterKey());
        return new EnvelopeCipher(masterKey);
    }
}
