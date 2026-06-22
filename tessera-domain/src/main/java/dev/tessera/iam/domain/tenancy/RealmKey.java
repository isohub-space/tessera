package dev.tessera.iam.domain.tenancy;

/**
 * The OIDC "realm", modelled as a tenant key rather than an aggregate
 *.
 *
 * <p>Tessera replaces Keycloak's mutable {@code RealmModel} with a
 * pure value: a "realm" <em>is</em> {@code (tenant, baseline)}. There is no
 * {@code Realm} object; isolation is expressed by this key flowing into every
 * scoped record and, in the shell, into Postgres RLS (fail-closed). This is
 * finer-grained than Keycloak realm separation.
 *
 * @param tenant   the owning tenant (never {@code null})
 * @param baseline the configuration baseline scope (never {@code null})
 */
public record RealmKey(TenantId tenant, BaselineId baseline) {

    public RealmKey {
        if (tenant == null) {
            throw new IllegalArgumentException("RealmKey tenant must not be null");
        }
        if (baseline == null) {
            throw new IllegalArgumentException("RealmKey baseline must not be null");
        }
    }
}
