package dev.tessera.observability.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A single, immutable record in a tamper-evident audit log.
 *
 * <p>Each entry hashes over the <em>previous</em> entry's hash, so the entries of
 * a tenant form a hash chain: altering, inserting, deleting or reordering any
 * entry changes its hash and breaks every subsequent link, which
 * {@link AuditChain#verify(java.util.List)} detects. The hash is computed over a
 * canonical serialization of the entry's content (independent of map iteration
 * order) so the digest is reproducible.</p>
 *
 * @param sequence   monotonic 0-based position of this entry within its tenant's
 *                   chain; the genesis entry is {@code 0}
 * @param tenant     the tenant this entry belongs to (chains are per-tenant); never
 *                   null/blank
 * @param eventType  a stable event-type name (e.g. {@code "token.issued"}); never
 *                   null/blank
 * @param timestamp  when the audited event occurred; never null
 * @param attributes free-form, non-secret attributes describing the event; copied
 *                   defensively and never null (may be empty)
 * @param previousHash lowercase-hex SHA-256 of the previous entry, or
 *                   {@link #GENESIS_HASH} for the first entry; never null
 * @param hash       lowercase-hex SHA-256 over this entry's canonical content;
 *                   never null
 */
public record AuditEntry(
        long sequence,
        String tenant,
        String eventType,
        Instant timestamp,
        Map<String, String> attributes,
        String previousHash,
        String hash) {

    /** Digest algorithm for the chain. */
    public static final String HASH_ALGORITHM = "SHA-256";

    /**
     * The {@code previousHash} of a genesis entry: 64 hex zeroes (the all-zero
     * SHA-256-width digest), denoting "no predecessor".
     */
    public static final String GENESIS_HASH = "0".repeat(64);

    private static final HexFormat HEX = HexFormat.of();

    public AuditEntry {
        if (sequence < 0) {
            throw new IllegalArgumentException("sequence must not be negative");
        }
        requireText(tenant, "tenant");
        requireText(eventType, "eventType");
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Objects.requireNonNull(previousHash, "previousHash must not be null");
        Objects.requireNonNull(hash, "hash must not be null");
        // Defensive, deterministic copy (TreeMap → stable key order independent of caller).
        attributes = Map.copyOf(new TreeMap<>(Objects.requireNonNull(attributes, "attributes must not be null")));
    }

    /**
     * Appends a new entry after {@code previous}, chaining over its hash. Use
     * {@link #genesis(String, String, Instant, Map)} for the first entry of a chain.
     *
     * @param previous   the immediately preceding entry of the same tenant's chain
     * @param eventType  the new entry's event type
     * @param timestamp  the new entry's event time
     * @param attributes the new entry's attributes
     * @return the appended, self-hashed entry
     */
    public static AuditEntry append(
            AuditEntry previous, String eventType, Instant timestamp, Map<String, String> attributes) {
        Objects.requireNonNull(previous, "previous must not be null");
        return create(previous.sequence() + 1, previous.tenant(), eventType, timestamp, attributes, previous.hash());
    }

    /**
     * Creates the genesis (first) entry of a tenant's chain, whose
     * {@code previousHash} is {@link #GENESIS_HASH}.
     *
     * @param tenant     the owning tenant
     * @param eventType  the entry's event type
     * @param timestamp  the entry's event time
     * @param attributes the entry's attributes
     * @return the genesis entry
     */
    public static AuditEntry genesis(
            String tenant, String eventType, Instant timestamp, Map<String, String> attributes) {
        return create(0L, tenant, eventType, timestamp, attributes, GENESIS_HASH);
    }

    private static AuditEntry create(
            long sequence,
            String tenant,
            String eventType,
            Instant timestamp,
            Map<String, String> attributes,
            String previousHash) {
        requireText(tenant, "tenant");
        requireText(eventType, "eventType");
        Objects.requireNonNull(timestamp, "timestamp must not be null");
        Map<String, String> sorted =
                Map.copyOf(new TreeMap<>(Objects.requireNonNull(attributes, "attributes must not be null")));
        String hash = computeHash(sequence, tenant, eventType, timestamp, sorted, previousHash);
        return new AuditEntry(sequence, tenant, eventType, timestamp, sorted, previousHash, hash);
    }

    /**
     * Recomputes this entry's hash from its content and the supplied predecessor
     * hash. {@link AuditChain#verify(java.util.List)} compares the result against
     * the stored {@link #hash()} to detect tampering.
     *
     * @return the recomputed lowercase-hex SHA-256
     */
    public String recomputeHash() {
        return computeHash(sequence, tenant, eventType, timestamp, attributes, previousHash);
    }

    /**
     * Canonical, injective serialization → SHA-256 → lowercase hex. Each field is
     * length-prefixed (or unambiguously delimited) so that no two distinct entries
     * can serialize to the same byte sequence; attribute keys are emitted in sorted
     * order so the digest does not depend on map iteration order.
     */
    private static String computeHash(
            long sequence,
            String tenant,
            String eventType,
            Instant timestamp,
            Map<String, String> attributes,
            String previousHash) {
        StringBuilder canonical = new StringBuilder(128);
        canonical.append("v1\n");
        field(canonical, "seq", Long.toString(sequence));
        field(canonical, "tenant", tenant);
        field(canonical, "event", eventType);
        field(canonical, "ts", timestamp.toString());
        field(canonical, "prev", previousHash);
        canonical.append("attrs:").append(attributes.size()).append('\n');
        // attributes is already a TreeMap-sorted copy, so iteration order is stable.
        for (Map.Entry<String, String> e : attributes.entrySet()) {
            field(canonical, e.getKey(), e.getValue());
        }
        byte[] digest = newDigest().digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
        return HEX.formatHex(digest);
    }

    /**
     * Appends {@code key.length:key=value.length:value\n}. Encoding the byte length
     * of each component makes the serialization injective — a delimiter appearing
     * inside a value cannot be confused with a field boundary.
     */
    private static void field(StringBuilder sb, String key, String value) {
        byte[] kb = key.getBytes(StandardCharsets.UTF_8);
        byte[] vb = value.getBytes(StandardCharsets.UTF_8);
        sb.append(kb.length).append(':').append(key)
          .append('=').append(vb.length).append(':').append(value).append('\n');
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is mandated on every conformant JRE; absence is non-recoverable.
            throw new IllegalStateException(HASH_ALGORITHM + " is required but unavailable", e);
        }
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
    }
}
