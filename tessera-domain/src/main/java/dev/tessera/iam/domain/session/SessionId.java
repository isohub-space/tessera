package dev.tessera.iam.domain.session;

import dev.tessera.iam.domain.tenancy.TimeOrderedUuid;
import java.util.UUID;

/**
 * Stable identity of an end-user login session.
 *
 * <p>Wraps a time-ordered UUID (v7): sessions are append-heavy and short-lived — the same
 * shape as the {@code refresh_token_family} and {@code auth_session} primary keys — so
 * generating one here keeps insert locality good on the backing table. This is also,
 * verbatim, the value carried by the session cookie: it is unguessable (128 bits of it
 * are CSPRNG-drawn) but not secret-bearing on its own — a stolen cookie is exactly as
 * dangerous as a stolen session, no more.
 *
 * @param value the session UUID (never {@code null})
 */
public record SessionId(UUID value) {

    public SessionId {
        if (value == null) {
            throw new IllegalArgumentException("SessionId value must not be null");
        }
    }

    /** Generates a fresh, time-ordered {@link SessionId}. */
    public static SessionId generate() {
        return new SessionId(TimeOrderedUuid.generate());
    }

    /**
     * Parses a {@link SessionId} from its canonical UUID string form (e.g. the raw cookie
     * value presented by a caller).
     *
     * @throws IllegalArgumentException if {@code value} is not a valid UUID
     */
    public static SessionId fromString(String value) {
        return new SessionId(UUID.fromString(value));
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
