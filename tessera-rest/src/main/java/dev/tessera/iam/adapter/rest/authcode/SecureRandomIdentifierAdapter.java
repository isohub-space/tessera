package dev.tessera.iam.adapter.rest.authcode;

import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import jakarta.enterprise.context.ApplicationScoped;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * CSPRNG-backed implementation of {@link OpaqueIdentifierPort}.
 *
 * <p>Randomness is an effect the functional core does not perform, so minting an
 * unguessable authorization code or token {@code jti} lives in the adapter shell. Both are
 * drawn from a single {@link SecureRandom} as 256-bit values and rendered base64url
 * (unpadded) — comfortably above the entropy floor RFC 6749 §10.10 requires for an
 * authorization code, and unique-with-overwhelming-probability for a {@code jti}.
 */
@ApplicationScoped
public class SecureRandomIdentifierAdapter implements OpaqueIdentifierPort {

    /** 256 bits of entropy per identifier. */
    private static final int IDENTIFIER_BYTES = 32;

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final SecureRandom random = new SecureRandom();

    @Override
    public String newAuthorizationCode() {
        return randomToken();
    }

    @Override
    public String newTokenId() {
        return randomToken();
    }

    private String randomToken() {
        byte[] bytes = new byte[IDENTIFIER_BYTES];
        random.nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }
}
