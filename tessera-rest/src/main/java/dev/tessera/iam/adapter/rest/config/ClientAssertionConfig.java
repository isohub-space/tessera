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
     * How many live spent {@code jti}s this instance remembers for one client. A client at the cap
     * has its own new assertions refused, never another client's. The default allows a sustained
     * three assertions a second for the default maximum lifetime.
     */
    @WithDefault("1000")
    int replayCacheMaxEntriesPerClient();

    /**
     * How many live spent {@code jti}s this instance remembers in total: a backstop well above what
     * the per-client caps add up to in practice. When it is reached, a new assertion is refused
     * rather than accepted without replay protection.
     */
    @WithDefault("100000")
    int replayCacheMaxEntries();
}
