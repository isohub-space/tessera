package dev.tessera.iam.launcher.health;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.observability.metrics.IamMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.inject.Instance;
import java.lang.reflect.Proxy;
import java.net.ConnectException;
import java.time.Duration;
import java.util.Optional;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.hibernate.reactive.mutiny.Mutiny;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Fail-closed readiness on a signing-key store outage, without a container: when the datasource
 * behind the signing keys fails, the probe reports the {@code iam-signing-key} subsystem DOWN and
 * names the failure, rather than reporting the last count it saw or UP.
 * {@code SigningKeyReadinessIT} covers the UP and empty cases against a real database.
 */
@DisplayName("SigningKeyReadinessCheck — a signing-key store outage reports the subsystem DOWN")
class SigningKeyReadinessOutageTest {

    @Test
    @DisplayName("a datasource failure is DOWN with the failure named, never UP")
    void datasourceFailureIsDown() {
        SigningKeyReadinessCheck check = checkOver(failingSessionFactory());

        HealthCheckResponse response = check.call().await().atMost(Duration.ofSeconds(10));

        assertThat(response.getName()).isEqualTo(SigningKeyReadinessCheck.NAME);
        assertThat(response.getStatus()).isEqualTo(HealthCheckResponse.Status.DOWN);
        assertThat(response.getData()).isPresent();
        assertThat(response.getData().get()).containsEntry("reason", "ConnectException");
    }

    private static SigningKeyReadinessCheck checkOver(Mutiny.SessionFactory factory) {
        SigningKeyReadinessCheck check = new SigningKeyReadinessCheck();
        check.enabled = true;
        check.configuredTenant = Optional.empty();
        check.fixedTenant = Optional.empty();
        check.metrics = new IamMetrics(new SimpleMeterRegistry());
        check.sessionFactory = resolvable(factory);
        check.init();
        return check;
    }

    /** A session factory whose every reactive operation fails as an unreachable database does. */
    private static Mutiny.SessionFactory failingSessionFactory() {
        return (Mutiny.SessionFactory) Proxy.newProxyInstance(
                SigningKeyReadinessOutageTest.class.getClassLoader(),
                new Class<?>[] {Mutiny.SessionFactory.class},
                (proxy, method, args) -> {
                    if (Uni.class.isAssignableFrom(method.getReturnType())) {
                        return Uni.createFrom().failure(new ConnectException("connection refused"));
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @SuppressWarnings("unchecked")
    private static Instance<Mutiny.SessionFactory> resolvable(Mutiny.SessionFactory factory) {
        return (Instance<Mutiny.SessionFactory>) Proxy.newProxyInstance(
                SigningKeyReadinessOutageTest.class.getClassLoader(),
                new Class<?>[] {Instance.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "isResolvable" -> true;
                    case "get" -> factory;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
