package dev.tessera.iam.launcher.observability;

import dev.tessera.observability.metrics.IamMetrics;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.lang.management.ManagementFactory;
import org.jboss.logging.Logger;

/**
 * Records server lifecycle metrics under the {@code iam.server.*} namespace as the
 * composition root boots.
 *
 * <p>On {@link StartupEvent} it increments {@code iam.server.started} and registers
 * {@code iam.server.uptime} (in seconds) as a gauge derived from the JVM's
 * RuntimeMXBean uptime, so a scrape always reflects how long this instance has been
 * running. The
 * JVM start-to-ready cold-start duration itself is captured by the platform's
 * {@code process_uptime_seconds} / startup logs and the native-image cold-start
 * benchmark; this binder adds the application-named counterpart that operators
 * filter dashboards on.</p>
 */
@ApplicationScoped
public class ServerStartupMetrics {

    private static final Logger LOG = Logger.getLogger(ServerStartupMetrics.class);

    private final IamMetrics metrics;

    @Inject
    public ServerStartupMetrics(IamMetrics metrics) {
        this.metrics = metrics;
    }

    void onStart(@Observes StartupEvent event) {
        metrics.increment("server", "started");
        metrics.gauge("server", "uptime",
                ManagementFactory.getRuntimeMXBean(),
                rt -> rt.getUptime() / 1000.0);
        LOG.debug("Recorded iam.server.started and registered iam.server.uptime gauge");
    }
}
