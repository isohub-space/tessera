package dev.tessera.iam.domain.credential;

/**
 * A password credential stored as an Argon2id PHC string
 *.
 *
 * <p>The {@code phc} value is a full PHC-format encoding (e.g.
 * {@code $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>}): it embeds the algorithm,
 * parameters, salt and digest, so verification needs nothing else. The raw
 * password is never represented in the domain.
 *
 * @param phc the Argon2id PHC string (never {@code null} or blank)
 */
public record PasswordHash(String phc) implements Credential {

    public PasswordHash {
        if (phc == null || phc.isBlank()) {
            throw new IllegalArgumentException("PasswordHash phc must not be blank");
        }
    }
}
