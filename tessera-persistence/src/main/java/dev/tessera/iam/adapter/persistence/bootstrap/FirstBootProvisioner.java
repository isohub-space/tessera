package dev.tessera.iam.adapter.persistence.bootstrap;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.CredentialEntity;
import dev.tessera.iam.adapter.persistence.entity.CredentialKind;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.adapter.persistence.entity.SigningKeyEntity;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.CredentialRepository;
import dev.tessera.iam.adapter.persistence.repository.OAuthClientRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import dev.tessera.iam.adapter.persistence.signingkey.KeyRotationService;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.hibernate.reactive.mutiny.Mutiny;
import org.jboss.logging.Logger;

/**
 * Provisions, on startup, what a fresh single-tenant deployment needs before it can serve a
 * relying party: an {@code ACTIVE} signing key for the fixed tenant, one confidential OAuth
 * client, and one password user — each only when absent, so a restart is a no-op and an
 * operator's later edits to a row are never overwritten from configuration.
 *
 * <p>This is deliberately a shell concern, not an API: tessera has no provisioning endpoint
 * (an unauthenticated one would be an authentication bypass, an authenticated one needs the
 * very identity this step creates), and the only alternative — hand-written SQL against
 * Argon2id hashes and envelope-encrypted key material — is exactly what cannot be authored by
 * hand. Configuration in, rows out, hashed and encrypted by the same code paths the request
 * path uses.
 *
 * <p>Requires {@code iam.tenancy.fixed-tenant}: without a fixed tenant there is no realm to
 * provision into and the step refuses to start rather than guess. Runs on the startup thread
 * and awaits the reactive work; Hibernate Reactive moves that work to a Vert.x context, which
 * is legal from a non-Vert.x thread (the same pattern the persistence integration tests use).
 */
@ApplicationScoped
public class FirstBootProvisioner {

    private static final Logger LOG = Logger.getLogger(FirstBootProvisioner.class);

    /** OWASP Argon2id baseline (m = 19 MiB, t = 2, p = 1); a one-off cost at first boot. */
    private static final Argon2Function ARGON2 = Argon2Function.getInstance(19456, 2, 1, 32, Argon2.ID);

    private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(2);
    private static final BaselineId ZERO_BASELINE = new BaselineId(new UUID(0L, 0L));
    private static final DateTimeFormatter KID_STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss").withZone(ZoneOffset.UTC);

    @Inject
    BootstrapConfig config;

    @Inject
    @ConfigProperty(name = "iam.tenancy.fixed-tenant")
    Optional<String> fixedTenant;

    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @Inject
    TenantScopedSession scoped;

    @Inject
    KeyRotationService keys;

    @Inject
    OAuthClientRepository clients;

    @Inject
    UserRepository users;

    @Inject
    CredentialRepository credentials;

    void onStart(@Observes StartupEvent event) {
        if (!config.enabled()) {
            return;
        }
        UUID tenant = fixedTenant.map(String::trim).filter(s -> !s.isEmpty()).map(UUID::fromString)
                .orElseThrow(() -> new IllegalStateException(
                        "iam.bootstrap.enabled requires iam.tenancy.fixed-tenant: first-boot "
                                + "provisioning has no realm to provision into"));
        if (!sessionFactory.isResolvable()) {
            throw new IllegalStateException(
                    "iam.bootstrap.enabled requires a reactive datasource");
        }
        RealmKey realm = new RealmKey(new TenantId(tenant), ZERO_BASELINE);
        provision(realm).await().atMost(STARTUP_TIMEOUT);
    }

    Uni<Void> provision(RealmKey realm) {
        return ensureSigningKey(realm)
                .chain(() -> ensureClient(realm))
                .chain(() -> ensureUser(realm));
    }

    private Uni<Void> ensureSigningKey(RealmKey realm) {
        UUID tenant = realm.tenant().value();
        return scoped.inTenant(tenant, session -> session
                        .createQuery("select count(k) from SigningKeyEntity k where k.state = :state", Long.class)
                        .setParameter("state", SigningKeyState.ACTIVE)
                        .getSingleResult())
                .chain(active -> {
                    if (active > 0) {
                        LOG.infof("bootstrap: tenant %s already holds %d ACTIVE signing key(s)", tenant, active);
                        return Uni.createFrom().voidItem();
                    }
                    KeyId kid = new KeyId("boot-" + KID_STAMP.format(Instant.now()));
                    LOG.infof("bootstrap: minting and activating signing key %s for tenant %s", kid.value(), tenant);
                    return keys.mintPending(realm, kid)
                            .chain(() -> keys.promoteToActive(realm, kid, Instant.now()));
                });
    }

    private Uni<Void> ensureClient(RealmKey realm) {
        BootstrapConfig.Client cfg = config.client();
        Optional<String> id = present(cfg.id());
        if (id.isEmpty()) {
            return Uni.createFrom().voidItem();
        }
        String secret = present(cfg.secret()).orElseThrow(() -> new IllegalStateException(
                "iam.bootstrap.client.secret is required when iam.bootstrap.client.id is set"));
        UUID tenant = realm.tenant().value();
        return clients.findByClientKey(tenant, realm.baseline().value(), id.get())
                .chain(existing -> {
                    if (existing != null) {
                        LOG.infof("bootstrap: client %s already registered", id.get());
                        return Uni.createFrom().voidItem();
                    }
                    OAuthClientEntity entity = new OAuthClientEntity();
                    entity.id = UUID.randomUUID();
                    entity.tenantId = tenant;
                    entity.baselineId = realm.baseline().value();
                    entity.clientKey = id.get();
                    entity.clientType = ClientType.CONFIDENTIAL;
                    entity.authMethod = "CLIENT_SECRET";
                    entity.secretHash = hash(secret);
                    entity.allowedGrants = String.join(",", cfg.grants());
                    entity.redirectUris = cfg.redirectUris()
                            .map(uris -> String.join(" ", uris))
                            .filter(s -> !s.isBlank())
                            .orElse(null);
                    entity.createdAt = Instant.now();
                    LOG.infof("bootstrap: registering confidential client %s (grants %s)",
                            id.get(), entity.allowedGrants);
                    return clients.persist(tenant, entity).replaceWithVoid();
                });
    }

    private Uni<Void> ensureUser(RealmKey realm) {
        BootstrapConfig.User cfg = config.user();
        Optional<String> username = present(cfg.username());
        if (username.isEmpty()) {
            return Uni.createFrom().voidItem();
        }
        String password = present(cfg.password()).orElseThrow(() -> new IllegalStateException(
                "iam.bootstrap.user.password is required when iam.bootstrap.user.username is set"));
        UUID tenant = realm.tenant().value();
        return users.findByUsername(tenant, username.get())
                .chain(existing -> {
                    if (existing != null) {
                        LOG.infof("bootstrap: user %s already exists", username.get());
                        return Uni.createFrom().voidItem();
                    }
                    UserEntity user = new UserEntity();
                    user.id = UUID.randomUUID();
                    user.tenantId = tenant;
                    user.baselineId = realm.baseline().value();
                    user.subjectId = UUID.randomUUID().toString();
                    user.username = username.get();
                    user.createdAt = Instant.now();

                    CredentialEntity credential = new CredentialEntity();
                    credential.id = UUID.randomUUID();
                    credential.tenantId = tenant;
                    credential.baselineId = realm.baseline().value();
                    credential.userId = user.id;
                    credential.kind = CredentialKind.PASSWORD_HASH;
                    credential.material = hash(password).getBytes(StandardCharsets.UTF_8);
                    credential.label = "bootstrap";
                    credential.createdAt = Instant.now();

                    LOG.infof("bootstrap: creating user %s with a password credential", username.get());
                    return users.persist(tenant, user)
                            .chain(() -> credentials.persist(tenant, credential))
                            .replaceWithVoid();
                });
    }

    private static Optional<String> present(Optional<String> value) {
        return value.map(String::trim).filter(s -> !s.isEmpty());
    }

    /** Argon2id PHC string, the format both verifiers parse their parameters from. */
    static String hash(String plaintext) {
        return Password.hash(plaintext).with(ARGON2).getResult();
    }
}
