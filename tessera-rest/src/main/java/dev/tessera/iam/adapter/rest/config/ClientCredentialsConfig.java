package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Configuration for the {@code client_credentials} grant (RFC 6749 §4.4).
 *
 * <p>{@link #enabled()} gates both the grant at {@code /token} and its advertisement in discovery,
 * so the two never disagree. Which clients may use it, with which scopes, audiences and roles, is
 * client registration data, not configuration here.
 */
@ConfigMapping(prefix = "iam.client-credentials")
public interface ClientCredentialsConfig {

    /** Whether {@code /token} serves {@code grant_type=client_credentials}. */
    @WithDefault("true")
    boolean enabled();

    /**
     * The lifetime of a {@code client_credentials} access token. Kept short: such a token has no
     * refresh token and revoking it is a no-op, so its lifetime is what bounds its use.
     */
    @WithDefault("PT5M")
    Duration accessTokenTtl();
}
