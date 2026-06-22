package dev.tessera.observability.audit;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.util.TypeLiteral;
import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionStage;

/**
 * A minimal test double for {@code Event<AuditEvent>} that records fired events so
 * a unit test can assert what the audit log published on the {@code iam.audit.*}
 * channel, without booting a CDI container.
 */
final class RecordingEvent implements Event<AuditEvent> {

    final List<AuditEvent> fired = new ArrayList<>();

    @Override
    public void fire(AuditEvent event) {
        fired.add(event);
    }

    @Override
    public <U extends AuditEvent> CompletionStage<U> fireAsync(U event) {
        throw new UnsupportedOperationException("not used in tests");
    }

    @Override
    public <U extends AuditEvent> CompletionStage<U> fireAsync(
            U event, jakarta.enterprise.event.NotificationOptions options) {
        throw new UnsupportedOperationException("not used in tests");
    }

    @Override
    public Event<AuditEvent> select(Annotation... qualifiers) {
        return this;
    }

    @Override
    public <U extends AuditEvent> Event<U> select(Class<U> subtype, Annotation... qualifiers) {
        throw new UnsupportedOperationException("not used in tests");
    }

    @Override
    public <U extends AuditEvent> Event<U> select(TypeLiteral<U> subtype, Annotation... qualifiers) {
        throw new UnsupportedOperationException("not used in tests");
    }
}
