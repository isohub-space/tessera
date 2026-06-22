package dev.tessera.iam.adapter.rest;

import dev.tessera.iam.adapter.rest.dto.ItemDto;
import dev.tessera.iam.domain.item.Item;

/** Maps domain {@link Item}s to REST-layer DTOs. */
final class ItemMapper {

    private ItemMapper() {}

    static ItemDto toDto(Item item) {
        return new ItemDto(item.id().value().toString(), item.name(), item.description());
    }
}
