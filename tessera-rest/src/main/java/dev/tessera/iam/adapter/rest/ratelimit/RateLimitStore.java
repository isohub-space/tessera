package dev.tessera.iam.adapter.rest.ratelimit;

/**
 * Outbound port for the ingress rate limiter: given a {@link RateLimitKey} and the
 * {@link RateLimitPolicy} that governs it, decide whether one request may proceed.
 *
 * <p><strong>Single-node today, distributed later.</strong> The shipped
 * {@link InMemoryRateLimitStore} keeps buckets in-process, so limits are per-node — an attacker
 * spread across {@code n} nodes gets {@code n×} the allowance. A clustered deployment backs this
 * port with a shared-cache backend (e.g. Infinispan) so a bucket is enforced fleet-wide; the
 * contract is unchanged, so the swap is a CDI-bean change with no caller impact.
 *
 * <p><strong>Must stay non-blocking.</strong> This is called from a JAX-RS request filter running
 * on the reactive I/O thread, so an implementation must not perform blocking I/O here. A
 * distributed backend must therefore front a local near-cache (keeping this call synchronous) or
 * the calling filter must migrate to an async ({@code Uni}-returning) server filter.
 */
interface RateLimitStore {

    /**
     * Attempts to consume one token for {@code key} under {@code policy}.
     *
     * @param key    the bucket identity
     * @param policy the bucket shape (capacity + refill) to apply if the bucket is new
     * @return a decision carrying whether the request is allowed and, if not, the whole-seconds
     *         {@code Retry-After} hint
     */
    RateLimitDecision tryAcquire(RateLimitKey key, RateLimitPolicy policy);

    /**
     * The outcome of a {@link #tryAcquire} call.
     *
     * @param allowed           {@code true} iff a token was consumed and the request may proceed
     * @param retryAfterSeconds whole seconds until a token is next available (0 when allowed)
     */
    record RateLimitDecision(boolean allowed, long retryAfterSeconds) {

        static RateLimitDecision allow() {
            return new RateLimitDecision(true, 0L);
        }

        static RateLimitDecision deny(long retryAfterSeconds) {
            return new RateLimitDecision(false, Math.max(0L, retryAfterSeconds));
        }
    }
}
