// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/** Limits on the JWT client assertions (RFC 7523) accepted at {@code /token}. */
@ConfigMapping(prefix = "iam.client-assertion")
public interface ClientAssertionConfig {

    /**
     * The longest validity an assertion may claim, from {@code iat} (or from now, without one) to
     * {@code exp}. It also bounds how long a {@code jti} must be remembered.
     */
    @WithDefault("PT5M")
    Duration maxLifetime();

    /** The clock skew tolerated on {@code exp}, {@code iat} and {@code nbf}. */
    @WithDefault("PT30S")
    Duration clockSkew();

    /**
     * How many spent {@code jti}s this instance remembers. When that many live ones are held, a
     * new assertion is refused rather than accepted without replay protection.
     */
    @WithDefault("100000")
    int replayCacheMaxEntries();
}
