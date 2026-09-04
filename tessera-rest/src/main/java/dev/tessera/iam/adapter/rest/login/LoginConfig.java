package dev.tessera.iam.adapter.rest.login;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.time.Duration;

/**
 * Configuration for the login/session surface (IAM-49).
 */
@ConfigMapping(prefix = "iam.login")
public interface LoginConfig {

    /** How long an established session remains valid. */
    @WithDefault("PT8H")
    Duration sessionTtl();
}
