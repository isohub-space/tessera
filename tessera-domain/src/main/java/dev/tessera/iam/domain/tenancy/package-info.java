/**
 * Tenancy value types for the Tessera domain.
 *
 * <p>Holds the self-contained {@link dev.tessera.iam.domain.tenancy.TenantId} /
 * {@link dev.tessera.iam.domain.tenancy.BaselineId} value objects and the
 * {@link dev.tessera.iam.domain.tenancy.RealmKey} that pairs them. "Realm == tenant
 * key, not an aggregate": every IAM record is scoped by a {@code RealmKey} so
 * isolation lives in the type system, mirrored by RLS in the persistence shell.
 *
 * <p>These types intentionally duplicate (rather than import) an external tenant registry's
 * identifiers to keep iam-domain a closed, framework-free functional core.
 */
package dev.tessera.iam.domain.tenancy;
