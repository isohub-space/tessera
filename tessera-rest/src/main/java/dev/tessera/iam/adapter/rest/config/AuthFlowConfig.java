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

    /**
     * Whether every access token issued on the authorization-code path must be
     * sender-constrained (RFC 9700 §2.2.1: DPoP for a public client, an mTLS certificate for
     * a confidential one). {@code true}, the default, is today's behaviour: a confidential
     * client that presents no certificate is refused a token.
     *
     * <p>Set to {@code false} for a deployment whose confidential clients cannot present a
     * client certificate at all — a back-end-for-frontend behind a TLS-terminating edge that
     * forwards no client certificate is the canonical case. Then a confidential client that
     * authenticates by secret or private-key JWT and presents no certificate receives a
     * plain Bearer token (RFC 6750). A client whose registered authentication method is mTLS
     * still needs its certificate, and a presented certificate still binds the token.
     */
    @WithDefault("true")
    boolean requireSenderConstraint();
}
