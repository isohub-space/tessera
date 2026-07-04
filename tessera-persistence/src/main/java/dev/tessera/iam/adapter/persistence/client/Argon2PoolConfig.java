package dev.tessera.iam.adapter.persistence.client;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Sizing for the dedicated Argon2id worker pool.
 *
 * <p>Argon2id verification is CPU- and memory-hard (~19 MiB per hash at the OWASP baseline). Run
 * on the shared Vert.x worker pool it could, under an invalid-credential flood, starve every other
 * blocking task and balloon peak memory. Giving it a small, separately-sized pool caps the number
 * of concurrent hashes — bounding both peak memory and the blast radius — while the credential
 * lockout upstream keeps most invalid attempts from ever reaching a hash.
 */
@ConfigMapping(prefix = "iam.argon2")
public interface Argon2PoolConfig {

    /**
     * Threads in the dedicated {@code argon2} worker pool. Kept small (well below the ~20-thread
     * default worker pool) so concurrent ~19 MiB hashes stay bounded.
     */
    @WithDefault("4")
    int poolSize();
}
