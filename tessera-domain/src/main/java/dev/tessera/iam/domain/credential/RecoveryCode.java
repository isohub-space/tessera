package dev.tessera.iam.domain.credential;

/**
 * A single-use account-recovery code, stored as a hash
 *.
 *
 * <p>Only the {@code hash} of the code is kept (same discipline as a password):
 * the user is shown the plaintext once at generation time and it never returns to
 * the domain. Consumption is a shell concern (compare-then-invalidate).
 *
 * @param hash the hash of the recovery code (never {@code null} or blank)
 */
public record RecoveryCode(String hash) implements Credential {

    public RecoveryCode {
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException("RecoveryCode hash must not be blank");
        }
    }
}
