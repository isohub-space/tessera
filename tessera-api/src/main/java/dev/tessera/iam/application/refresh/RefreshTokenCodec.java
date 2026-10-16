package dev.tessera.iam.application.refresh;

import dev.tessera.iam.domain.refresh.FamilyId;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pure wire-format and hashing helper for opaque refresh tokens.
 *
 * <p>A refresh token is {@code base64url(familyId 16 bytes) + "." + secret}: the family id is
 * embedded (non-secret) so a presented token routes to its family without any request header, and
 * the {@code secret} is a 256-bit CSPRNG value from {@link
 * dev.tessera.iam.application.port.out.OpaqueIdentifierPort#newRefreshToken()}. Neither half
 * contains a {@code '.'} (both are unpadded base64url), so the single separator is unambiguous.
 *
 * <p>Only the {@code secret} is hashed for storage (the family id is public, so hashing it adds
 * nothing). Hashing is a deterministic, effect-free {@code SHA-256} — a 256-bit random secret needs
 * no memory-hard KDF and no constant-time compare on this side (the store compares hash strings; the
 * security boundary is the atomic compare-and-swap, not a timing-sensitive verify). {@code
 * MessageDigest} is pure JDK, so this lives in the framework-free application layer, mirroring the
 * domain's PKCE verifier.
 */
public final class RefreshTokenCodec {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();
    private static final int UUID_BYTES = 16;

    private RefreshTokenCodec() {
    }

    /** Assembles the opaque wire token from a family id and a fresh secret. */
    public static String assemble(FamilyId id, String secret) {
        if (id == null || secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("id and secret must be non-null; secret non-blank");
        }
        return encodeFamilyId(id) + "." + secret;
    }

    /**
     * Parses a presented wire token into its family id and secret. Any malformedness (wrong shape,
     * bad base64, wrong id length) yields {@link Optional#empty()} rather than an exception — a
     * malformed token is a non-match the caller collapses to {@code invalid_grant}, never a server
     * error.
     */
    public static Optional<Parsed> parse(String presented) {
        if (presented == null) {
            return Optional.empty();
        }
        int dot = presented.indexOf('.');
        if (dot <= 0 || dot >= presented.length() - 1) {
            return Optional.empty();
        }
        String idPart = presented.substring(0, dot);
        String secret = presented.substring(dot + 1);
        try {
            byte[] idBytes = B64URL_DEC.decode(idPart);
            if (idBytes.length != UUID_BYTES) {
                return Optional.empty();
            }
            return Optional.of(new Parsed(new FamilyId(uuidFromBytes(idBytes)), secret));
        } catch (IllegalArgumentException notBase64) {
            return Optional.empty();
        }
    }

    /** The base64url-unpadded SHA-256 of the token secret — the value stored and compared. */
    public static String sha256(String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("secret must not be null");
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.US_ASCII));
            return B64URL.encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available", e);
        }
    }

    /**
     * The secret of the token that succeeds {@code presentedSecret} in family {@code id}, derived as
     * {@code base64url(HMAC-SHA256(key, label | familyId | presentedSecret | salt))}: 256 bits, the
     * same shape as a random secret. {@code salt} is random per rotation and stored with the family.
     * The input is the predecessor's <em>secret</em>, never its hash: the store keeps the hash next
     * to the salt, so a hash-based derivation would let the key plus a read of the store reproduce
     * the live token without any token at all.
     *
     * <p>Used only when a reuse grace is configured. Deriving the successor from its predecessor
     * makes a rotation idempotent: the predecessor presented again inside the grace yields exactly
     * the successor the first presentation received, so concurrent requests of one session all end
     * with the same live token, and no branch of the family ever exists. Computing a successor needs
     * the server key, the rotation's salt from the store <em>and</em> the predecessor token itself:
     * an old token plus the key does not reveal a newer token, nor does the key plus a read of the
     * store, nor a read of the store alone.
     *
     * @param key           the server-side derivation key (at least 32 bytes)
     * @param id            the family id
     * @param presentedSecret the secret of the token being succeeded (the presented token's secret part)
     * @param salt            the rotation's random salt
     * @return the successor's secret
     */
    public static String successorSecret(byte[] key, FamilyId id, String presentedSecret, String salt) {
        if (key == null || key.length < 32) {
            throw new IllegalArgumentException("successor key must be at least 32 bytes");
        }
        if (id == null || presentedSecret == null || presentedSecret.isBlank() || salt == null
                || salt.isBlank()) {
            throw new IllegalArgumentException("id, presentedSecret and salt must be non-null and non-blank");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] out = mac.doFinal(
                    ("tessera-refresh-successor-v2|" + id.value() + "|" + presentedSecret + "|" + salt)
                            .getBytes(StandardCharsets.US_ASCII));
            return B64URL.encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 must be available", e);
        }
    }

    private static String encodeFamilyId(FamilyId id) {
        UUID u = id.value();
        ByteBuffer bb = ByteBuffer.allocate(UUID_BYTES);
        bb.putLong(u.getMostSignificantBits());
        bb.putLong(u.getLeastSignificantBits());
        return B64URL.encodeToString(bb.array());
    }

    private static UUID uuidFromBytes(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return new UUID(bb.getLong(), bb.getLong());
    }

    /** A parsed refresh token: its family id and the raw secret (to be hashed for comparison). */
    public record Parsed(FamilyId id, String secret) {
    }
}
