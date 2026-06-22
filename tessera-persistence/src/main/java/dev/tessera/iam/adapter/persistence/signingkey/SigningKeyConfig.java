package dev.tessera.iam.adapter.persistence.signingkey;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Configuration for the development DB-backed signing-key provider.
 *
 * <p>Holds the dev master key used to envelope-encrypt private keys and the maximum
 * signing TTL that drives rotation. A production deployment would not use the dev
 * master key at all — wrapping is delegated to a KMS/HSM behind the provider port.
 */
@ConfigMapping(prefix = "iam.keys")
public interface SigningKeyConfig {

    /**
     * Base64-encoded 256-bit master key that wraps each per-key data key.
     *
     * <p>The default is a well-known, <strong>development-only</strong> value: it lets
     * the service boot in {@code dev} without external key management. It must be
     * overridden in any non-development deployment (and there it is superseded by a
     * KMS/HSM).
     */
    @WithDefault("ZGV2LW1hc3Rlci1rZXktMzItYnl0ZXMtQUVTMjU2ISE=")
    String masterKey();

    /** Token issuer ({@code iss}) stamped on keys minted by the rotation service. */
    @WithDefault("https://localhost:8090")
    String issuer();

    /** Maximum age an ACTIVE key may sign for before it is due to retire. */
    @WithDefault("PT24H")
    String maxSigningTtl();
}
