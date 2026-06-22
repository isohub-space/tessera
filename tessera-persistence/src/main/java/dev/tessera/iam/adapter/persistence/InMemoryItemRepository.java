package dev.tessera.iam.adapter.persistence;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory {@link ItemRepositoryPort} seeded with a small sample so the
 * service exercises the REST contract end-to-end without a database.
 *
 * <p>Replace it with a Hibernate Reactive Panache (or reactive-pg-client)
 * adapter when a real datastore is introduced — consumers depend only on the
 * port, so nothing else changes.
 */
@ApplicationScoped
public class InMemoryItemRepository implements ItemRepositoryPort {

    private final Map<ItemId, Item> store = new LinkedHashMap<>();

    @PostConstruct
    void seed() {
        for (Item item : sampleItems()) {
            store.put(item.id(), item);
        }
    }

    @Override
    public Uni<Item> findById(ItemId id) {
        return Uni.createFrom().item(() -> store.get(id));
    }

    @Override
    public Multi<Item> listAll() {
        return Multi.createFrom().iterable(store.values());
    }

    private static java.util.List<Item> sampleItems() {
        return java.util.List.of(
                new Item(
                        ItemId.fromString("00000000-0000-0000-0000-000000000001"),
                        "First Sample",
                        "A seeded sample item."),
                new Item(
                        ItemId.fromString("00000000-0000-0000-0000-000000000002"),
                        "Second Sample",
                        "Another seeded sample item."));
    }
}
