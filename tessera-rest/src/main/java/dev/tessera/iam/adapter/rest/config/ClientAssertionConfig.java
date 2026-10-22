// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;
import java.util.Map;

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
     * How many live spent {@code jti}s this instance remembers for one realm, across its clients. A
     * realm at the cap has its own new assertions refused, never another realm's.
     */
    @WithDefault("10000")
    int replayCacheMaxEntriesPerRealm();

    /**
     * How many live spent {@code jti}s this instance remembers in total, across realms: it bounds
     * the memory the store can take. When it is reached, a new assertion is refused rather than
     * accepted without replay protection.
     */
    @WithDefault("100000")
    int replayCacheMaxEntries();

    /**
     * External issuers whose JWT client assertions may be trusted, by a name of the operator's
     * choosing: {@code iam.client-assertion.trusted-issuers.<name>.issuer} and {@code .jwks-uri}.
     * Both must be {@code https}. The key-set URL is configured, never discovered, so no issuer
     * metadata can point tessera at another host. None by default.
     */
    Map<String, TrustedIssuer> trustedIssuers();

    /** How long a fetched issuer key set is used before it is fetched again. */
    @WithDefault("PT10M")
    Duration jwksCacheTtl();

    /**
     * The shortest interval between two fetches of one issuer's key set, so an assertion naming an
     * unknown {@code kid}, or an unreachable issuer, cannot make tessera fetch on every request.
     */
    @WithDefault("PT30S")
    Duration jwksMinRefreshInterval();

    /** One trusted external issuer. */
    interface TrustedIssuer {

        /** The issuer identifier, exactly as its tokens carry it in {@code iss}. */
        String issuer();

        /** The {@code https} URL of its JWK Set. */
        String jwksUri();
    }
}
