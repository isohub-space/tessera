package dev.tessera.iam.domain.tenancy;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Generator of time-ordered UUIDs (UUID version 7, RFC 9562).
 *
 * <p>A v7 UUID places a 48-bit Unix-millisecond timestamp in its most significant
 * bits, so values generated in time order also sort in lexical / byte order. This
 * matters for append-heavy tables that use the UUID as their primary key: a random
 * v4 key scatters inserts uniformly across the B-tree index, fragmenting it and
 * dirtying many pages per insert, whereas a v7 key appends to the right-hand edge of
 * the index, keeping it dense and the working set small. Tables that are written far
 * more often than they are looked up by id (sessions, token families) use this
 * generator; low-volume tables keep random v4.
 *
 * <p>Layout (RFC 9562 §5.7): bits 0–47 hold the timestamp, the version nibble (bits
 * 48–51) is {@code 0b0111} (7), the variant bits (bits 64–65) are {@code 0b10}, and
 * every remaining bit is drawn from a {@link SecureRandom} so that two UUIDs minted
 * within the same millisecond still differ with overwhelming probability.
 */
public final class TimeOrderedUuid {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TimeOrderedUuid() {
    }

    /**
     * Generates a fresh time-ordered UUID (version 7).
     *
     * @return a new {@link UUID} whose high bits encode the current wall-clock instant
     */
    public static UUID generate() {
        long timestampMillis = System.currentTimeMillis();

        // High 64 bits: 48-bit millisecond timestamp, then the version nibble, then
        // the high 12 bits of randomness filling out the word.
        long randA = RANDOM.nextInt(0x1000); // 12 random bits below the version nibble
        long mostSignificant = (timestampMillis << 16)
                | (0x7L << 12)               // version 7
                | randA;

        // Low 64 bits: variant bits 0b10 in the two most significant positions, then
        // 62 bits of randomness.
        long randB = RANDOM.nextLong();
        long leastSignificant = (randB & 0x3FFFFFFFFFFFFFFFL) // clear top two bits
                | 0x8000000000000000L;                        // variant 0b10

        return new UUID(mostSignificant, leastSignificant);
    }
}
