package dev.tessera.iam.adapter.rest.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;
import java.util.Optional;

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

    /**
     * How long after a rotation the token it superseded may be presented again <em>by the same
     * confidential client</em> and receive the same successor, instead of being treated as a replay
     * that revokes the family. Covers a confidential client that sends concurrent requests with one
     * refresh token, for example a gateway serving parallel calls of one browser session from
     * several instances.
     *
     * <p>A deliberate, bounded relaxation of strict rotation, of the kind several authorization
     * servers offer as a refresh-token "reuse interval" or "grace period". Never applied to public
     * clients, whose replay detection stays strict. Within the window a predecessor presented by a
     * party that also holds the client's credentials is not detected, so keep it to seconds. The
     * window is measured on server clocks, assumed synchronised. {@code PT0S} (the default) turns
     * it off; a positive value requires {@link #successorKey()}.
     */
    @WithDefault("PT0S")
    Duration reuseGrace();

    /**
     * Base64 key (at least 32 bytes) successor secrets are derived with when {@link #reuseGrace()}
     * is positive, together with a random per-rotation salt kept in the store, so a re-presented
     * predecessor yields the same successor on every node. A server secret; the key alone, or the
     * store alone, does not reveal a token. Changing it makes only in-flight reissues fail.
     */
    Optional<String> successorKey();
}
