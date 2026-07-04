package dev.tessera.iam.adapter.rest.ratelimit;

/**
 * The shape of a token bucket: its burst {@code capacity} and steady-state
 * {@code refillPerSecond}. A {@link RateLimitKey} is limited by one policy per surface.
 *
 * @param capacity        maximum tokens the bucket holds (the allowed burst)
 * @param refillPerSecond tokens replenished per second (the sustained rate)
 */
record RateLimitPolicy(int capacity, double refillPerSecond) {

    RateLimitPolicy {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        if (refillPerSecond <= 0) {
            throw new IllegalArgumentException("refillPerSecond must be positive");
        }
    }
}
