package dev.tessera.iam.adapter.persistence.bootstrap;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.util.List;
import java.util.Optional;

/**
 * First-boot provisioning for a single-tenant deployment ({@code iam.bootstrap.*}).
 *
 * <p>Everything here is optional and off by default. Secrets are read from configuration so
 * that a deployment can source them from its secret manager through the environment; they
 * are hashed (Argon2id) before they touch the database and are never logged.
 */
@ConfigMapping(prefix = "iam.bootstrap")
public interface BootstrapConfig {

    /** Whether the startup provisioning step runs at all. */
    @WithDefault("false")
    boolean enabled();

    /** The confidential OAuth client to provision when absent. */
    Client client();

    /** The password user to provision when absent. */
    User user();

    interface Client {

        /** The wire {@code client_id}; blank leaves no client provisioned. */
        Optional<String> id();

        /** The plaintext {@code client_secret}, hashed before storage. */
        Optional<String> secret();

        /** Registered redirect URIs (comma-separated in configuration), exact-match. */
        Optional<List<String>> redirectUris();

        /** Allowed grants, as wire values. */
        @WithDefault("authorization_code,refresh_token")
        List<String> grants();
    }

    interface User {

        /** The login username; blank leaves no user provisioned. */
        Optional<String> username();

        /** The plaintext password, hashed before storage. */
        Optional<String> password();
    }
}
