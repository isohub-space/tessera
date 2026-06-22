package dev.tessera.iam.domain.item;

import java.util.UUID;

/** Identity of an {@link Item}. A framework-free value object. */
public record ItemId(UUID value) {

    public ItemId {
        if (value == null) {
            throw new IllegalArgumentException("ItemId value must not be null");
        }
    }

    /** Parses an {@link ItemId} from its canonical UUID string form. */
    public static ItemId fromString(String value) {
        return new ItemId(UUID.fromString(value));
    }

    /** Generates a fresh random {@link ItemId}. */
    public static ItemId generate() {
        return new ItemId(UUID.randomUUID());
    }
}
