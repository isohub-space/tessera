package dev.tessera.iam.domain.item;

/**
 * Sample domain aggregate for Tessera.
 *
 * <p>Pure Java — no Quarkus, Hibernate or {@code jakarta.*} imports. Replace it
 * with the real model of the service; the surrounding ports, adapters and
 * boundary tests show the conventions to follow.
 *
 * @param id          stable identity
 * @param name        short human-readable name (required, non-blank)
 * @param description longer free-text description (may be empty, never null)
 */
public record Item(ItemId id, String name, String description) {

    public Item {
        if (id == null) {
            throw new IllegalArgumentException("Item id must not be null");
        }
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Item name must not be blank");
        }
        if (description == null) {
            description = "";
        }
    }

    /** Convenience factory generating a fresh identity. */
    public static Item of(String name, String description) {
        return new Item(ItemId.generate(), name, description);
    }
}
