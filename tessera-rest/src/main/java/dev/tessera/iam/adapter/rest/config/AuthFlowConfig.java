package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Lifetimes for the Authorization Code + PKCE flow.
 *
 * <p>All three are deliberately short-lived. The authorization code is single-use and
 * exchanged immediately, so its TTL is tight (RFC 6749 §4.1.2 / §10.5 recommend ≤ 10
 * minutes — this default is far tighter). Access- and ID-token lifetimes are bounded so a
 * leaked token has a small blast radius; longer-lived access is the job of a refresh token,
 * which is a separate grant.
 */
@ConfigMapping(prefix = "iam.authflow")
public interface AuthFlowConfig {

    /**
     * How long a single-use authorization code remains redeemable before it expires. Kept
     * short because the code is exchanged for tokens immediately after issuance.
     */
    @WithDefault("PT1M")
    Duration codeTtl();

    /** The lifetime of an issued RFC 9068 JWT access token. */
    @WithDefault("PT5M")
    Duration accessTokenTtl();

    /** The lifetime of an issued OIDC ID token. */
    @WithDefault("PT5M")
    Duration idTokenTtl();
}
