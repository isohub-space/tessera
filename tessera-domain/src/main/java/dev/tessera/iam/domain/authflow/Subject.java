package dev.tessera.iam.domain.authflow;

import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * The resolved end-user principal once an identifier has been matched
 *.
 *
 * <p>An immutable correlation value: the stable {@code sub} the issued tokens will
 * carry, scoped to a {@link RealmKey}. Per the design's boundary with an external tenant registry,
 * IAM's user is a <em>credential-bearing projection</em> correlated by {@code sub} —
 * so this record carries only the opaque subject identifier and its realm, never
 * profile attributes (those are fetched later through a claim-source port and
 * assembled by {@link dev.tessera.iam.domain.authflow.ClaimContributor}).
 *
 * @param subjectId the stable OIDC {@code sub} (never {@code null} or blank)
 * @param realm     the realm this subject was resolved within (never {@code null})
 */
public record Subject(String subjectId, RealmKey realm) {

    public Subject {
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("Subject subjectId must not be null or blank");
        }
        if (realm == null) {
            throw new IllegalArgumentException("Subject realm must not be null");
        }
    }
}
