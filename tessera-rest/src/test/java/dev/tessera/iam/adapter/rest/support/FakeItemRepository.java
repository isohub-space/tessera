package dev.tessera.iam.adapter.rest.support;

import io.quarkus.test.Mock;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import dev.tessera.iam.domain.item.Item;
import dev.tessera.iam.domain.item.ItemId;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Empty test double for {@link ItemRepositoryPort} (the sample read API's repository, whose
 * real implementation lives in the persistence module). Present only so the REST adapter
 * boots as a standalone Quarkus app in this module's tests without a datasource; the auth
 * flow does not use it.
 */
@Mock
@ApplicationScoped
public class FakeItemRepository implements ItemRepositoryPort {

    @Override
    public Uni<Item> findById(ItemId id) {
        return Uni.createFrom().nullItem();
    }

    @Override
    public Multi<Item> listAll() {
        return Multi.createFrom().empty();
    }
}
