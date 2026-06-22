package dev.tessera.iam.adapter.rest.config;

import dev.tessera.iam.application.ItemService;
import dev.tessera.iam.application.port.in.QueryItemsUseCase;
import dev.tessera.iam.application.port.out.ItemRepositoryPort;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

/**
 * CDI wiring for the read use case.
 *
 * <p>The application service is framework-free, so the adapter constructs it
 * from the injected outbound repository port and exposes it as a CDI bean.
 */
@ApplicationScoped
public class UseCaseProducer {

    @Produces
    @ApplicationScoped
    QueryItemsUseCase queryItemsUseCase(ItemRepositoryPort repository) {
        return new ItemService(repository);
    }
}
