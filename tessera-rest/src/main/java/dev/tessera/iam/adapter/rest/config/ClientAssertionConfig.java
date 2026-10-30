// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;
import java.util.Map;

/**
 * Limits on the JWT client assertions (RFC 7523) accepted at {@code /token}, {@code /introspect}
 * and {@code /revoke}.
 */
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
     * How many live spent {@code jti}s this instance remembers for one client at {@code /token}. A
     * client at the cap has its own new assertions there refused, never another client's. The
     * default allows a sustained three assertions a second for the default maximum lifetime.
     */
    @WithDefault("1000")
    int replayCacheMaxEntriesPerClient();

    /**
     * How many live spent {@code jti}s this instance remembers for one client at {@code /introspect}
     * and {@code /revoke}, a budget apart from {@code /token}'s: a resource server that introspects
     * by assertion spends one {@code jti} per call, at a rate its own callers drive, and at this cap
     * is refused at those two endpoints only, never at {@code /token}. The {@code jti}s are one
     * namespace all the same: an assertion spent at any of the three endpoints is refused at the
     * others. The per-realm and total caps apply to this budget separately, so the store holds at
     * most twice {@link #replayCacheMaxEntries()}. At most {@link #replayCacheMaxEntriesPerRealm()}.
     * Such a resource server should cache introspection results rather than introspect every
     * request.
     */
    @WithDefault("1000")
    int introspectionReplayCacheMaxEntriesPerClient();

    /**
     * How many live spent {@code jti}s this instance remembers for one realm, across its clients, in
     * each of the two budgets ({@code /token}; {@code /introspect} and {@code /revoke}). A realm at
     * the cap has its own new assertions in that budget refused, never another realm's.
     */
    @WithDefault("10000")
    int replayCacheMaxEntriesPerRealm();

    /**
     * How many live spent {@code jti}s this instance remembers in total, across realms, in each of
     * the two budgets: twice this bounds the memory the store can take. When it is reached, a new
     * assertion in that budget is refused rather than accepted without replay protection.
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
     * unknown {@code kid}, or an unreachable issuer, cannot make tessera fetch on every request. At
     * least {@code PT5S} and shorter than {@link #jwksCacheTtl()}, or the server refuses to start.
     */
    @WithDefault("PT30S")
    Duration jwksMinRefreshInterval();

    /** One trusted external issuer. */
    interface TrustedIssuer {

        /** The issuer identifier, exactly as its tokens carry it in {@code iss}. */
        String issuer();

        /** The {@code https} URL of its JWK Set. */
        String jwksUri();

        /**
         * The longest validity its tokens may claim, from {@code iat} (or now) to {@code exp}; at
         * most {@code PT1H}. A cloud platform's workload identity token typically lives one hour.
         */
        @WithDefault("PT5M")
        Duration maxLifetime();

        /**
         * Whether its tokens must carry a {@code jti}. Off by default: platform tokens often carry
         * none.
         */
        @WithDefault("false")
        boolean requireJti();

        /**
         * Whether a {@code jti} may be presented only once. Off by default: a platform token is
         * typically exchanged again and again until the platform rotates it, so its {@code jti} is
         * recorded and reuse is allowed until {@code exp}. Turn it on for an issuer that mints a
         * fresh token for every request.
         */
        @WithDefault("false")
        boolean enforceSingleUse();
    }
}
