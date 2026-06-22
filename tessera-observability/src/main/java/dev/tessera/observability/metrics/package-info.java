/**
 * Application metrics for the authorization server.
 *
 * <p>{@link dev.tessera.observability.metrics.IamMetrics} is the single naming
 * authority and factory for every application meter, enforcing the
 * {@code iam.<subsystem>.<metric>} convention and delegating to the injected
 * Micrometer registry so meters are exposed on the shared Prometheus endpoint.
 */
package dev.tessera.observability.metrics;
