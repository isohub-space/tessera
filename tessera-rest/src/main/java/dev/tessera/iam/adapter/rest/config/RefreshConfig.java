package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Configuration for rotating refresh tokens (RFC 6749 §6, OAuth 2.0 Security BCP / RFC 9700 §4.14).
 *
 * <p>{@link #enabled()} gates both the initial issuance of a refresh token on the authorization-code
 * path and its redemption at the refresh grant; when {@code false} the server behaves exactly as if
 * refresh tokens did not exist. Single-use rotation is always on when enabled — there is
 * deliberately no "rotation off" knob, since a non-rotating mode would defeat the reuse-detection
 * the security model depends on. {@link #refreshTokenTtl()} bounds a family's lifetime.
 */
@ConfigMapping(prefix = "iam.refresh")
public interface RefreshConfig {

    /** Master switch for issuing and redeeming refresh tokens. */
    @WithDefault("true")
    boolean enabled();

    /** How long a refresh-token family remains redeemable before it expires. */
    @WithDefault("P30D")
    Duration refreshTokenTtl();
}
