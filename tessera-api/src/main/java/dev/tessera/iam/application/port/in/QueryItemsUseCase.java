package dev.tessera.iam.application.port.in;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;

/** Inbound port: the read use case exposed by Tessera. */
public interface QueryItemsUseCase {

    /**
     * Finds a single item by id.
     *
     * @param id the item identity
     * @return a {@link Uni} emitting the item, or {@code null} if none exists
     */
    Uni<Item> findById(ItemId id);

    /**
     * Lists every known item.
     *
     * @return a {@link Multi} of the items (possibly empty)
     */
    Multi<Item> listAll();
}
