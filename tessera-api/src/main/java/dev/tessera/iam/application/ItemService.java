package dev.tessera.iam.application;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.in.QueryItemsUseCase;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;

/**
 * Application service implementing the read use case by delegating to the
 * outbound repository port.
 *
 * <p>Framework-free (no CDI annotations); an adapter wires it to a concrete
 * {@link ItemRepositoryPort} implementation and exposes it as a bean.
 */
public final class ItemService implements QueryItemsUseCase {

    private final ItemRepositoryPort repository;

    public ItemService(ItemRepositoryPort repository) {
        if (repository == null) {
            throw new IllegalArgumentException("repository must not be null");
        }
        this.repository = repository;
    }

    @Override
    public Uni<Item> findById(ItemId id) {
        return repository.findById(id);
    }

    @Override
    public Multi<Item> listAll() {
        return repository.listAll();
    }
}
