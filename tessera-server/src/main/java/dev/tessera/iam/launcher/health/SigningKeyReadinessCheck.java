package dev.tessera.iam.launcher.health;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.persistence.DevTenant;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Readiness gate: the IAM service is
 * only ready to sign tokens when the dev tenant owns at least one {@code ACTIVE}
 * signing key — otherwise {@code /q/health/ready} is <strong>DOWN</strong>, fail-closed.
 *
 * <p>Scoped to the fixed {@link DevTenant#ID}: it opens a transaction, sets
 * {@code app.tenant_id} on the very same reactive connection (the same chokepoint the
 * RLS policies rely on), then counts {@code signing_key} rows with
 * {@code state = 'ACTIVE'}. Request-scoped X-Tenant-Id propagation arrives in
 *; for this slice the readiness tenant is the fixed dev tenant.</p>
 *
 * <p><strong>%test pitfall.</strong> The existing launcher {@code @QuarkusTest}s boot
 * Docker-free with no datasource, so there is no {@link Mutiny.SessionFactory} bean to
 * query. Two guards keep them green:</p>
 * <ol>
 *   <li>The check is <em>config-disabled</em> under {@code %test} via
 *       {@code iam.readiness.signing-key.enabled=false} — when disabled it returns UP
 *       without touching the (absent) datasource, so {@code HealthAndMetricsTest}'s
 *       aggregate-UP assertion holds.</li>
 *   <li>Even when enabled, the {@code SessionFactory} is injected as an
 *       {@link Instance} and resolved lazily: if it is unresolvable the check reports
 *       DOWN rather than failing CDI wiring at boot.</li>
 * </ol>
 *
 * <p>The DOWN-when-empty / UP-when-ACTIVE behaviour against a real datasource is
 * proven by {@code SigningKeyReadinessIT} in {@code iam-persistence} (Testcontainers).</p>
 */
@Readiness
@ApplicationScoped
public class SigningKeyReadinessCheck implements HealthCheck {

    static final String NAME = "iam-signing-key";

    /** Bound on the readiness query so a stuck datasource can't hang the probe. */
    private static final Duration QUERY_TIMEOUT = Duration.ofSeconds(5);

    @Inject
    @ConfigProperty(name = "iam.readiness.signing-key.enabled", defaultValue = "true")
    boolean enabled;

    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @Override
    public HealthCheckResponse call() {
        // Config-disabled (e.g. %test, no datasource): do not touch persistence; the
        // gate is simply not part of the readiness contract in that mode.
        if (!enabled) {
            return HealthCheckResponse.named(NAME)
                    .withData("enabled", false)
                    .up()
                    .build();
        }
        if (!sessionFactory.isResolvable()) {
            return HealthCheckResponse.named(NAME)
                    .withData("reason", "no reactive datasource")
                    .down()
                    .build();
        }
        long activeKeys = countActiveDevTenantKeys(sessionFactory.get());
        return HealthCheckResponse.named(NAME)
                .withData("tenant", DevTenant.ID.toString())
                .withData("activeSigningKeys", activeKeys)
                .status(activeKeys > 0)
                .build();
    }

    private long countActiveDevTenantKeys(Mutiny.SessionFactory factory) {
        return factory
                .withTransaction((session, tx) ->
                        applyTenantScope(session, DevTenant.ID)
                                .chain(() -> session
                                        .createQuery(
                                                "select count(k) from SigningKeyEntity k "
                                                + "where k.state = :state",
                                                Long.class)
                                        .setParameter("state", SigningKeyState.ACTIVE)
                                        .getSingleResult()))
                .await()
                .atMost(QUERY_TIMEOUT);
    }

    private static Uni<String> applyTenantScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }
}
