package dev.tessera.observability.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link DegradedSubsystemRegistry}: status transitions, the
 * fail-soft default, and the WARN-on-degraded contract.
 *
 * <p>JBoss {@code Logger} is JUL-backed, so the WARN assertions attach a JUL
 * {@link Handler} to the registry's logger category and inspect the captured
 * records — no coupling to a specific log backend.</p>
 */
@DisplayName("DegradedSubsystemRegistry")
class DegradedSubsystemRegistryTest {

    private DegradedSubsystemRegistry registry;
    private Logger julLogger;
    private CapturingHandler handler;
    private Level previousLevel;

    @BeforeEach
    void setUp() {
        registry = new DegradedSubsystemRegistry();
        julLogger = Logger.getLogger(DegradedSubsystemRegistry.class.getName());
        previousLevel = julLogger.getLevel();
        julLogger.setLevel(Level.ALL);
        handler = new CapturingHandler();
        julLogger.addHandler(handler);
    }

    @AfterEach
    void tearDown() {
        julLogger.removeHandler(handler);
        julLogger.setLevel(previousLevel);
    }

    @Test
    @DisplayName("an unregistered subsystem defaults to DEGRADED (fail-soft)")
    void unregisteredDefaultsToDegraded() {
        assertThat(registry.statusOf("never-registered")).isEqualTo(SubsystemStatus.DEGRADED);
    }

    @Test
    @DisplayName("register then report walks UP / DEGRADED / DOWN transitions")
    void transitions() {
        registry.register("kafka", SubsystemStatus.DEGRADED);
        assertThat(registry.statusOf("kafka")).isEqualTo(SubsystemStatus.DEGRADED);

        registry.report("kafka", SubsystemStatus.UP);
        assertThat(registry.statusOf("kafka")).isEqualTo(SubsystemStatus.UP);

        registry.report("kafka", SubsystemStatus.DOWN);
        assertThat(registry.statusOf("kafka")).isEqualTo(SubsystemStatus.DOWN);
    }

    @Test
    @DisplayName("allUp() reflects whether every registered subsystem is UP")
    void allUp() {
        registry.register("a", SubsystemStatus.UP);
        registry.register("b", SubsystemStatus.UP);
        assertThat(registry.allUp()).isTrue();

        registry.report("b", SubsystemStatus.DEGRADED);
        assertThat(registry.allUp()).isFalse();
    }

    @Test
    @DisplayName("snapshot() is an immutable copy")
    void snapshotImmutable() {
        registry.register("a", SubsystemStatus.UP);
        var snap = registry.snapshot();
        assertThat(snap).containsEntry("a", SubsystemStatus.UP);
        assertThatThrownBy(() -> snap.put("b", SubsystemStatus.UP))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("registering a subsystem DEGRADED on startup logs WARN once")
    void warnsOnDegradedStartup() {
        registry.register("orekit", SubsystemStatus.DEGRADED);

        List<LogRecord> warnings = handler.warnings();
        assertThat(warnings).hasSize(1);
        assertThat(warnings.get(0).getMessage()).contains("orekit").contains("DEGRADED");
    }

    @Test
    @DisplayName("a transition into DOWN logs WARN; staying DOWN does not re-log")
    void warnsOnDownTransitionOnce() {
        registry.report("gpu", SubsystemStatus.DOWN);
        registry.report("gpu", SubsystemStatus.DOWN); // unchanged → no re-log

        assertThat(handler.warnings()).hasSize(1);
        assertThat(handler.warnings().get(0).getMessage()).contains("gpu").contains("DOWN");
    }

    @Test
    @DisplayName("reporting UP never logs WARN")
    void upDoesNotWarn() {
        registry.report("kafka", SubsystemStatus.UP);
        assertThat(handler.warnings()).isEmpty();
    }

    @Test
    @DisplayName("recovering UP then degrading again logs WARN on the new degraded transition")
    void warnsAgainAfterRecovery() {
        registry.report("kafka", SubsystemStatus.DEGRADED); // warn #1
        registry.report("kafka", SubsystemStatus.UP);       // no warn
        registry.report("kafka", SubsystemStatus.DEGRADED); // warn #2

        assertThat(handler.warnings()).hasSize(2);
    }

    @Test
    @DisplayName("null/blank names and null status are rejected")
    void rejectsInvalidInput() {
        assertThatThrownBy(() -> registry.report(null, SubsystemStatus.UP))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.report("  ", SubsystemStatus.UP))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> registry.report("kafka", null))
                .isInstanceOf(NullPointerException.class);
    }

    /** Captures WARN+ records published to the registry's JUL category. */
    private static final class CapturingHandler extends Handler {
        private final List<LogRecord> records = new CopyOnWriteArrayList<>();

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
            // nothing buffered
        }

        @Override
        public void close() {
            records.clear();
        }

        List<LogRecord> warnings() {
            return records.stream()
                    .filter(r -> r.getLevel().intValue() >= Level.WARNING.intValue())
                    .toList();
        }
    }
}
