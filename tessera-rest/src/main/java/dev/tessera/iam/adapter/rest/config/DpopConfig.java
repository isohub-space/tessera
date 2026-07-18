package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Acceptance parameters for DPoP proof validation (RFC 9449).
 *
 * <p>A DPoP proof carries an {@code iat} timestamp and a unique {@code jti}; the server
 * accepts a proof only within a tight freshness window and only once (single-use replay
 * defence). The window must be short enough to bound how long a captured proof could be
 * replayed against another node before its {@code jti} is universally rejected, yet loose
 * enough to tolerate reasonable client/server clock skew.
 */
@ConfigMapping(prefix = "iam.dpop")
public interface DpopConfig {

    /**
     * How far in the <em>past</em> a proof's {@code iat} may be and still be accepted. Also
     * bounds how long a spent {@code jti} is retained for replay detection — after this the
     * proof would be rejected as stale regardless, so its {@code jti} can be forgotten.
     */
    @WithDefault("PT1M")
    Duration proofMaxAge();

    /**
     * Allowed <em>future</em> skew for a proof's {@code iat} — a small tolerance so a client
     * whose clock runs slightly fast is not rejected. Kept tight; a proof dated far in the
     * future is refused.
     */
    @WithDefault("PT5S")
    Duration clockSkew();
}
