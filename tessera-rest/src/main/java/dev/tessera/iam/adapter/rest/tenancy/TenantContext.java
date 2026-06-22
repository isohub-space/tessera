package dev.tessera.iam.adapter.rest.tenancy;

import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.RequestScoped;
import java.util.Optional;

/**
 * Request-scoped holder for the realm ({@code tenant} + {@code baseline}) resolved for
 * the current call.
 *
 * <p>This is the single place the rest of the request reads the caller's tenant from:
 * the {@link TenantResolutionFilter} resolves the realm once, at the very start of the
 * request, and stores it here; resources and downstream collaborators read it back
 * rather than re-parsing headers. The realm is <strong>never</strong> inferred from the
 * request body — only from the trusted ingress headers the filter validates.
 *
 * <p><strong>Reactive propagation.</strong> A {@code @RequestScoped} bean is bound to the
 * request's context, which the runtime carries across reactive ({@code Uni}) hops via the
 * duplicated context, so a handler that suspends and resumes on a different worker thread
 * still reads the same realm. There is no thread-local to leak between pooled requests.
 *
 * <p>It is deliberately fail-closed at read time: {@link #realm()} throws if no realm was
 * bound, so a code path that reaches the database or a token signer without having gone
 * through the resolution filter fails loudly instead of operating tenant-less.
 */
@RequestScoped
public class TenantContext {

    private RealmKey realm;

    /**
     * Binds the resolved realm for this request. Called once by the resolution filter.
     *
     * @param realm the realm resolved from the trusted ingress headers (never {@code null})
     */
    public void bind(RealmKey realm) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        this.realm = realm;
    }

    /**
     * The realm bound for this request.
     *
     * @return the realm
     * @throws IllegalStateException if no realm was bound — a fail-closed guard against a
     *                               path that bypassed the resolution filter
     */
    public RealmKey realm() {
        if (realm == null) {
            throw new IllegalStateException(
                    "No tenant bound for this request — tenant resolution did not run");
        }
        return realm;
    }

    /** The bound realm if present, else empty — for callers that tolerate its absence. */
    public Optional<RealmKey> realmIfPresent() {
        return Optional.ofNullable(realm);
    }
}
