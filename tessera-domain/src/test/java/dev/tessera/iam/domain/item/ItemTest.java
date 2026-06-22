package dev.tessera.iam.domain.item;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Item — domain invariants")
class ItemTest {

    @Test
    @DisplayName("rejects a blank name")
    void rejectsBlankName() {
        ItemId id = ItemId.generate();
        assertThatThrownBy(() -> new Item(id, "  ", "desc"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("normalises a null description to empty")
    void normalisesNullDescription() {
        Item item = new Item(ItemId.generate(), "Telemetry", null);
        assertThat(item.description()).isEmpty();
    }

    @Test
    @DisplayName("of(..) generates a fresh identity")
    void ofGeneratesIdentity() {
        Item item = Item.of("Telemetry", "A sample item");
        assertThat(item.id()).isNotNull();
        assertThat(item.name()).isEqualTo("Telemetry");
    }
}
