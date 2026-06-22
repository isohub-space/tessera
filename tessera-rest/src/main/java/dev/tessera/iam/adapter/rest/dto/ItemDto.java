package dev.tessera.iam.adapter.rest.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/** Wire representation of an item returned by the REST API. */
@Schema(name = "Item", description = "A sample item exposed by Tessera.")
public record ItemDto(
        @Schema(description = "Stable item identity (UUID).") String id,
        @Schema(description = "Short human-readable name.") String name,
        @Schema(description = "Longer free-text description.") String description) {}
