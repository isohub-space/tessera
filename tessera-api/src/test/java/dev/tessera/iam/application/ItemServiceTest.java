package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ItemService — delegates to the outbound port")
class ItemServiceTest {

    private static final class FakeRepository implements ItemRepositoryPort {
        private final List<Item> items;

        FakeRepository(List<Item> items) {
            this.items = items;
        }

        @Override
        public Uni<Item> findById(ItemId id) {
            return Uni.createFrom()
                    .item(() -> items.stream().filter(i -> i.id().equals(id)).findFirst().orElse(null));
        }

        @Override
        public Multi<Item> listAll() {
            return Multi.createFrom().iterable(items);
        }
    }

    @Test
    @DisplayName("rejects a null repository")
    void rejectsNullRepository() {
        try {
            new ItemService(null);
            assertThat(false).as("expected IllegalArgumentException").isTrue();
        } catch (IllegalArgumentException expected) {
            assertThat(expected).hasMessageContaining("repository");
        }
    }

    @Test
    @DisplayName("findById returns the matching item")
    void findByIdReturnsItem() {
        Item item = Item.of("Telemetry", "sample");
        ItemService service = new ItemService(new FakeRepository(List.of(item)));

        Item found = service.findById(item.id()).await().indefinitely();

        assertThat(found).isEqualTo(item);
    }

    @Test
    @DisplayName("listAll streams every item")
    void listAllStreamsItems() {
        Item a = Item.of("A", "first");
        Item b = Item.of("B", "second");
        ItemService service = new ItemService(new FakeRepository(List.of(a, b)));

        List<Item> all = service.listAll().collect().asList().await().indefinitely();

        assertThat(all).containsExactly(a, b);
    }
}
