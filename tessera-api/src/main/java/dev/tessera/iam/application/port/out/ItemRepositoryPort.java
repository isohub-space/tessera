package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;

/**
 * Outbound port for reading {@link Item}s from a store. Implemented by an
 * adapter in the persistence module; the application depends only on this
 * interface.
 */
public interface ItemRepositoryPort {

    /**
     * Finds a single item by id.
     *
     * @param id the item identity
     * @return a {@link Uni} emitting the item, or {@code null} if none exists
     */
    Uni<Item> findById(ItemId id);

    /**
     * Lists every stored item.
     *
     * @return a {@link Multi} of the items (possibly empty)
     */
    Multi<Item> listAll();
}
