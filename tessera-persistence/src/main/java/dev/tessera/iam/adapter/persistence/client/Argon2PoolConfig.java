package dev.tessera.iam.adapter.persistence.client;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Sizing for the dedicated Argon2id worker pool.
 *
 * <p>Argon2id verification is CPU- and memory-hard (~19 MiB per hash at the OWASP baseline). Run
 * on the shared Vert.x worker pool it could, under an invalid-credential flood, starve every other
 * blocking task and balloon peak memory. Giving it a small, separately-sized pool caps the number
 * of concurrent hashes — bounding both peak memory and the blast radius — and
 * {@link Argon2Admission} bounds how many may wait for it, overall and per tenant, and for how long.
 */
@ConfigMapping(prefix = "iam.argon2")
public interface Argon2PoolConfig {

    /**
     * Threads in the dedicated {@code argon2} worker pool. Kept small (well below the ~20-thread
     * default worker pool) so concurrent ~19 MiB hashes stay bounded.
     */
    @WithDefault("4")
    int poolSize();

    /**
     * Verifications that may wait for a worker beyond the {@link #poolSize()} running ones. Past
     * {@code poolSize + maxWaiting} admitted at once, a request is refused at once with {@code 503}.
     * Provisional until a perf run measures it.
     */
    @WithDefault("16")
    int maxWaiting();

    /**
     * The fraction of {@code poolSize + maxWaiting} one tenant may hold, so a flood through one
     * tenant leaves room for the others. Provisional until a perf run measures it.
     */
    @WithDefault("0.5")
    double tenantShare();

    /**
     * How long a verification may wait for a worker before it is refused with {@code 503}; it then
     * never runs. Provisional until a perf run measures it.
     */
    @WithDefault("PT1S")
    Duration waitDeadline();
}
