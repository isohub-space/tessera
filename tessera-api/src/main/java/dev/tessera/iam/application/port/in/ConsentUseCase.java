package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Set;

/**
 * Inbound port for the consent step of the login flow: records, and later checks, which
 * scopes an authenticated end user has agreed to release to a given client.
 *
 * <p><strong>Granularity (IAM-49 AC4).</strong> Consent is recorded per {@code (subject,
 * client)}, not per {@code (subject, client, scope)}: {@link #hasConsented} asks whether the
 * user has already agreed to <em>at least</em> the requested scope set, and
 * {@link #recordConsent} replaces whatever the user previously agreed to for that client with
 * the new set (a strict narrowing or widening both simply re-record). This is the coarser of
 * the two reasonable granularities named in the story's estimate note; it matches the
 * {@code consent} table's {@code UNIQUE (tenant, baseline, user, client)} constraint exactly,
 * so no migration is needed to ship it. Splitting to per-scope consent (letting a user grant
 * {@code profile} but withhold {@code email} for the same client) is a follow-on, not a
 * blocker — the schema would need a new grain, so it is deliberately not done speculatively.
 */
public interface ConsentUseCase {

    /**
     * Whether {@code subjectId} has already consented to release at least {@code scopes} to
     * {@code clientId}.
     *
     * @param realm     the realm to check within (never {@code null})
     * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
     * @param clientId  the client being authorized (never {@code null})
     * @param scopes    the scopes the current request needs (never {@code null}; empty means
     *                  "no scope-bearing consent is required", which always passes)
     * @return a {@link Uni} emitting {@code true} iff a prior consent covers every requested
     *         scope
     */
    Uni<Boolean> hasConsented(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes);

    /**
     * Records that {@code subjectId} has consented to release {@code scopes} to
     * {@code clientId}, replacing any prior consent for that {@code (subject, client)} pair.
     *
     * @param realm     the realm to record within (never {@code null})
     * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
     * @param clientId  the client being granted consent (never {@code null})
     * @param scopes    the scopes consented to (never {@code null}; may be empty)
     * @return a {@link Uni} completing once the consent is durably recorded
     */
    Uni<Void> recordConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes);
}
