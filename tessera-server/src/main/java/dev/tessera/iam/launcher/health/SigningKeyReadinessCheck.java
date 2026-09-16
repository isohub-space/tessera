package dev.tessera.iam.launcher.health;

import dev.tessera.iam.adapter.persistence.DevTenant;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import dev.tessera.observability.metrics.IamMetrics;
import io.smallrye.health.api.AsyncHealthCheck;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Readiness gate: the IAM service is only ready to sign tokens when the readiness tenant
 * owns at least one {@code ACTIVE} signing key — otherwise {@code /q/health/ready} is
 * <strong>DOWN</strong>, fail-closed.
 *
 * <p><strong>Non-blocking.</strong> This is an {@link AsyncHealthCheck}: the probe returns
 * the {@link Uni} of the reactive query instead of awaiting it. SmallRye Health runs
 * synchronous checks on a worker thread, and Hibernate Reactive refuses a blocking
 * {@code await()} from there ({@code HR000068}), so a synchronous check against a reactive
 * session factory can never report UP in a packaged run — it errors. The query is still
 * bounded by {@link #QUERY_TIMEOUT} so a stuck datasource cannot hang the probe.</p>
 *
 * <p><strong>Which tenant.</strong> RLS on {@code signing_key} is keyed by tenant, so the
 * probe must bind one. It is resolved once, at construction, in this order:</p>
 * <ol>
 *   <li>{@code iam.readiness.signing-key.tenant}, when set;</li>
 *   <li>the deployment's {@code iam.tenancy.fixed-tenant}, when the server runs in
 *       single-tenant mode;</li>
 *   <li>the fixed {@link DevTenant#ID}, which is what the {@code %dev} seed provisions.</li>
 * </ol>
 * A multi-tenant deployment names its readiness tenant explicitly; a single-tenant one
 * needs nothing beyond its fixed tenant.
 *
 * <p><strong>%test pitfall.</strong> The existing launcher {@code @QuarkusTest}s boot
 * Docker-free with no datasource, so there is no {@link Mutiny.SessionFactory} bean to
 * query. Two guards keep them green:</p>
 * <ol>
 *   <li>The check is <em>config-disabled</em> under {@code %test} via
 *       {@code iam.readiness.signing-key.enabled=false} — when disabled it returns UP
 *       without touching the (absent) datasource.</li>
 *   <li>Even when enabled, the {@code SessionFactory} is injected as an
 *       {@link Instance} and resolved lazily: if it is unresolvable the check reports
 *       DOWN rather than failing CDI wiring at boot.</li>
 * </ol>
 *
 * <p>The DOWN-when-empty / UP-when-ACTIVE behaviour against a real datasource is
 * proven by {@code SigningKeyReadinessIT} in {@code tessera-persistence} (Testcontainers).</p>
 *
 * <p><strong>Metric.</strong> Each probe also publishes the observed active-signing-key
 * count to the {@code iam.key.active} gauge (subsystem {@code key}). The gauge samples a
 * value the check refreshes whenever it runs, so scraping it adds no datasource load of
 * its own; an operator can alert on it dropping to zero, which is the same fail-closed
 * condition the readiness gate enforces, and watch it move across a key rotation as a
 * {@code PENDING} key is promoted to {@code ACTIVE}.</p>
 */
@Readiness
@ApplicationScoped
public class SigningKeyReadinessCheck implements AsyncHealthCheck {

    static final String NAME = "iam-signing-key";

    /** Bound on the readiness query so a stuck datasource can't hang the probe. */
    private static final Duration QUERY_TIMEOUT = Duration.ofSeconds(5);

    @Inject
    @ConfigProperty(name = "iam.readiness.signing-key.enabled", defaultValue = "true")
    boolean enabled;

    @Inject
    @ConfigProperty(name = "iam.readiness.signing-key.tenant")
    Optional<String> configuredTenant;

    @Inject
    @ConfigProperty(name = "iam.tenancy.fixed-tenant")
    Optional<String> fixedTenant;

    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @Inject
    IamMetrics metrics;

    private UUID tenantId;

    /**
     * Last active-key count observed by a probe, sampled by the {@code iam.key.active}
     * gauge. {@code -1} until the first probe completes (distinguishing "not yet probed"
     * from an observed zero).
     */
    private final AtomicLong lastActiveKeyCount = new AtomicLong(-1L);

    @PostConstruct
    void init() {
        tenantId = readinessTenant(configuredTenant, fixedTenant);
        metrics.gauge("key", "active", lastActiveKeyCount, AtomicLong::doubleValue);
    }

    /**
     * Resolves the tenant the probe binds: the explicit readiness tenant, else the
     * deployment's fixed tenant, else the development tenant. A configured value that is
     * not a UUID fails startup rather than silently probing the wrong tenant.
     */
    static UUID readinessTenant(Optional<String> configured, Optional<String> fixed) {
        return firstPresent(configured)
                .or(() -> firstPresent(fixed))
                .map(SigningKeyReadinessCheck::parse)
                .orElse(DevTenant.ID);
    }

    private static Optional<String> firstPresent(Optional<String> value) {
        return value.map(String::trim).filter(s -> !s.isEmpty());
    }

    private static UUID parse(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "The readiness tenant must be a UUID (iam.readiness.signing-key.tenant / "
                            + "iam.tenancy.fixed-tenant)", e);
        }
    }

    @Override
    public Uni<HealthCheckResponse> call() {
        // Config-disabled (e.g. %test, no datasource): do not touch persistence; the
        // gate is simply not part of the readiness contract in that mode.
        if (!enabled) {
            return Uni.createFrom().item(HealthCheckResponse.named(NAME)
                    .withData("enabled", false)
                    .up()
                    .build());
        }
        if (!sessionFactory.isResolvable()) {
            return Uni.createFrom().item(HealthCheckResponse.named(NAME)
                    .withData("reason", "no reactive datasource")
                    .down()
                    .build());
        }
        return countActiveKeys(sessionFactory.get())
                .ifNoItem().after(QUERY_TIMEOUT).fail()
                .map(activeKeys -> {
                    lastActiveKeyCount.set(activeKeys);
                    return HealthCheckResponse.named(NAME)
                            .withData("tenant", tenantId.toString())
                            .withData("activeSigningKeys", activeKeys)
                            .status(activeKeys > 0)
                            .build();
                })
                .onFailure().recoverWithItem(failure -> HealthCheckResponse.named(NAME)
                        .withData("tenant", tenantId.toString())
                        .withData("reason", failure.getClass().getSimpleName())
                        .down()
                        .build());
    }

    private Uni<Long> countActiveKeys(Mutiny.SessionFactory factory) {
        return factory.withTransaction((session, tx) ->
                applyTenantScope(session, tenantId)
                        .chain(() -> session
                                .createQuery(
                                        "select count(k) from SigningKeyEntity k "
                                        + "where k.state = :state",
                                        Long.class)
                                .setParameter("state", SigningKeyState.ACTIVE)
                                .getSingleResult()));
    }

    private static Uni<String> applyTenantScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }
}
