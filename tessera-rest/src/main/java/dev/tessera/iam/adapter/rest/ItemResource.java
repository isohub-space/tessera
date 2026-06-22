package dev.tessera.iam.adapter.rest;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.rest.dto.ItemDto;
import dev.tessera.iam.adapter.rest.problem.ProblemResponse;
import dev.tessera.iam.application.port.in.QueryItemsUseCase;
import dev.tessera.iam.domain.item.ItemId;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * Reactive read API for Tessera.
 *
 * <ul>
 *   <li>{@code GET /api/v1/items}      — all items</li>
 *   <li>{@code GET /api/v1/items/{id}} — one item by id</li>
 * </ul>
 */
@Path("/api/v1/items")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "items", description = "Sample item catalogue exposed by Tessera.")
public class ItemResource {

    @Inject
    QueryItemsUseCase useCase;

    @GET
    @Operation(operationId = "listItems", summary = "List all items")
    @APIResponse(responseCode = "200", description = "Collection of items.")
    public Multi<ItemDto> list() {
        return useCase.listAll().onItem().transform(ItemMapper::toDto);
    }

    @GET
    @Path("/{id}")
    @Operation(operationId = "getItem", summary = "Get an item by its id")
    @APIResponse(responseCode = "200", description = "Item found.")
    @APIResponse(
            responseCode = "404",
            description = "No item exists for the given id.",
            content =
                    @Content(
                            mediaType = ProblemResponse.MEDIA_TYPE,
                            schema = @Schema(implementation = ProblemResponse.class)))
    public Uni<Response> getById(
            @Parameter(description = "Item id (UUID).") @PathParam("id") String id) {
        ItemId itemId = parseId(id);
        return useCase
                .findById(itemId)
                .onItem()
                .ifNotNull()
                .transform(item -> Response.ok(ItemMapper.toDto(item)).build())
                .onItem()
                .ifNull()
                .continueWith(() -> ProblemResponse.notFound(id));
    }

    private static ItemId parseId(String id) {
        try {
            return ItemId.fromString(id);
        } catch (IllegalArgumentException ex) {
            throw new WebApplicationException(
                    ProblemResponse.badRequest("Invalid item id (expected a UUID): " + id));
        }
    }
}
