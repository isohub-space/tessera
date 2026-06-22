package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Configuration for the OIDC discovery and JWKS endpoints.
 *
 * <p>The {@code issuer} is server configuration, resolved per realm — it is
 * <strong>never</strong> derived from the request {@code Host} header, so a relying
 * party cannot trick the server into advertising a foreign issuer. For the baseline tier
 * a single configured issuer serves every realm; per-realm / per-tenant issuers are a
 * later tier.
 *
 * <p>The cache and dwell timings encode the publish-before-sign safety margin. The JWKS
 * {@code Cache-Control} max-age must be strictly shorter than the time a freshly minted
 * key stays {@code PENDING} before it is promoted to {@code ACTIVE} and signs (the
 * "PENDING dwell"). With {@code ttl < dwell}, a verifier's cached JWKS is guaranteed to
 * expire — forcing a re-fetch that picks up the {@code PENDING} key — before that key
 * ever signs a token.
 */
@ConfigMapping(prefix = "iam.oidc")
public interface OidcDiscoveryConfig {

    /**
     * The exact issuer identifier advertised in discovery and stamped on tokens. The
     * configured value is used verbatim (it is the OIDC {@code iss}); endpoint URLs are
     * derived from it.
     */
    @WithDefault("http://localhost:8080")
    String issuer();

    /** JWKS / discovery caching parameters. */
    Jwks jwks();

    /** JWKS caching parameters. */
    interface Jwks {

        /**
         * The {@code Cache-Control: max-age} (seconds) served with the JWKS (and
         * discovery) responses. Must be strictly less than {@link #pendingDwellSeconds()}
         * so a verifier re-fetches and pre-trusts a {@code PENDING} key before it signs.
         */
        @WithDefault("30")
        long cacheTtlSeconds();
    }

    /**
     * How long (seconds) a newly minted key stays {@code PENDING} — published but not yet
     * signing — before it is promoted to {@code ACTIVE}. The JWKS cache TTL is kept
     * strictly below this value so every verifier re-fetches the JWKS within the dwell
     * window. Must be greater than {@code jwks.cache-ttl-seconds}.
     */
    @WithDefault("120")
    long pendingDwellSeconds();
}
