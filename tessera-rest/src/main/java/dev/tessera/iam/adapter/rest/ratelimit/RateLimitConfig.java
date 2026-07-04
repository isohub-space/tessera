package dev.tessera.iam.adapter.rest.ratelimit;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Rate-limiting and brute-force-lockout knobs for the edge (RFC 9700 §2 — credential-stuffing
 * and token-guessing mitigation). All have safe defaults; the whole feature can be toggled off
 * with {@code iam.ratelimit.enabled=false} (the flow tests do this so their bursts never trip
 * the limiter, opting back in per test with a {@code @TestProfile}).
 */
@ConfigMapping(prefix = "iam.ratelimit")
public interface RateLimitConfig {

    /** Master switch. When {@code false}, the filter and the credential lockout are no-ops. */
    @WithDefault("true")
    boolean enabled();

    /**
     * Hard cap on the number of distinct rate-limit buckets held in memory. Bounds the blast
     * radius of a key-rotation flood; once reached, an untracked key is treated as throttled.
     */
    @WithDefault("100000")
    int maxTrackedKeys();

    /** {@code /token} burst capacity — it is the token-guessing surface, so kept tight. */
    @WithDefault("20")
    int tokenCapacity();

    /** {@code /token} sustained rate (tokens replenished per minute). */
    @WithDefault("20")
    int tokenRefillPerMinute();

    /** {@code /authorize} burst capacity — looser than {@code /token} (redirects, retries). */
    @WithDefault("60")
    int authorizeCapacity();

    /** {@code /authorize} sustained rate (tokens replenished per minute). */
    @WithDefault("60")
    int authorizeRefillPerMinute();

    /**
     * Consecutive wrong secrets for one {@code (tenant, client_id)} before the credential path is
     * locked out — short-circuiting to {@code invalid_client} without running Argon2, which
     * relieves the hashing pool under an invalid-credential flood.
     */
    @WithDefault("10")
    int credentialMaxFailures();

    /** How long a {@code (tenant, client_id)} stays locked out after the failure threshold. */
    @WithDefault("PT5M")
    Duration credentialLockout();
}
