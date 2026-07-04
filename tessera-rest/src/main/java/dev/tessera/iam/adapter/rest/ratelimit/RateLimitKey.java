package dev.tessera.iam.adapter.rest.ratelimit;

import java.util.UUID;

/**
 * The identity of a rate-limit bucket: the protected {@code surface}, the trustworthy
 * {@code tenant} axis (gateway-asserted, already validated upstream), and a {@code principal}
 * (the {@code client_id} where legible, else a best-effort source IP).
 *
 * <p>Value-based (a {@code record}) so it is a stable {@code HashMap} key. The tenant is always
 * present for a resolved request; it may be {@code null} only on the fail-closed coarse path
 * where tenant resolution somehow did not bind a realm — in which case the bucket degrades to a
 * per-{@code (surface, principal)} bucket rather than being skipped.
 *
 * @param surface   which endpoint / dimension this bucket protects
 * @param tenant    the resolved tenant UUID (the load-bearing axis), or {@code null} if unbound
 * @param principal the {@code client_id} or source IP that identifies the caller
 */
record RateLimitKey(Surface surface, UUID tenant, String principal) {

    /** The rate-limited dimensions. IP-keyed surfaces are a secondary, coarser axis. */
    enum Surface {
        /** {@code /authorize}, keyed on the request's {@code client_id}. */
        AUTHORIZE,
        /** {@code /authorize}, keyed on source IP — a coarse backstop when {@code client_id} rotates. */
        AUTHORIZE_IP,
        /** {@code /token}, keyed on the HTTP-Basic {@code client_id} when present, else source IP. */
        TOKEN
    }
}
