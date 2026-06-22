package dev.tessera.iam.domain.credential;

/**
 * A TOTP (RFC 6238) shared secret.
 *
 * <p>Held as a Base32-encoded secret. Unlike the other factors this is a
 * <em>symmetric</em> secret the server must keep; in the shell it is stored
 * encrypted-at-rest. The live one-time codes derived from it are never modelled in
 * the domain.
 *
 * @param base32 the Base32-encoded TOTP secret (never {@code null} or blank)
 */
public record TotpSecret(String base32) implements Credential {

    public TotpSecret {
        if (base32 == null || base32.isBlank()) {
            throw new IllegalArgumentException("TotpSecret base32 must not be blank");
        }
    }
}
