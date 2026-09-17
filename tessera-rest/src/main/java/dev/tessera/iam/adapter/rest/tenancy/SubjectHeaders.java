package dev.tessera.iam.adapter.rest.tenancy;

/**
 * The trusted ingress header contract for the authenticated end-user subject.
 *
 * <p><strong>Trust boundary — read this before deploying tessera as a public origin.</strong>
 * {@link #SUBJECT} ({@value #SUBJECT}) rests on the same edge contract as
 * {@link TenantHeaders#TENANT}: a gateway asserts it and strips any client-supplied value.
 * Where no such gateway exists, neither header's contract is enforced by the act of reading
 * it — {@code TenantResolutionFilter} performs no trust check on {@code X-Tenant-Id}, it
 * resolves whatever is there and binds it, and absent the filter below the same would be true
 * here. Both are stated as gateway-asserted only in prose ({@code TenantHeaders}'s javadoc,
 * and {@code AuthorizeResource}'s "an upstream authenticating proxy" language for this one);
 * a deployment that exposes either header to callers whose edge does not strip client-supplied
 * values is not a supported mode. Each header now has its own way out of that mode, and they
 * are not the same way — see the next paragraph.
 *
 * <p>{@link dev.tessera.iam.adapter.rest.session.SessionCookieFilter} is the one exception:
 * it enforces this header's boundary at the application layer too, <strong>default-closed</strong>
 * — unless a deployment explicitly sets {@code iam.subject.trust-header=true}, any inbound
 * value for {@code X-Subject-Id} is stripped before anything reads it, and a verified session
 * cookie is the only remaining way to establish a subject. Setting that flag re-opens the
 * older "upstream authenticating proxy injects this header directly" mode, and doing so is
 * exactly as consequential as it sounds: with it set, tessera again trusts the header
 * verbatim, so the deployment's edge MUST strip any client-supplied value, or
 * {@code X-Subject-Id} becomes a complete, trivial authentication bypass — any caller sets
 * {@code X-Subject-Id: <victim-sub>} and is treated as that user with no credential at all.
 * {@code X-Tenant-Id}'s answer is a different one: a standalone public origin sets
 * {@code iam.tenancy.fixed-tenant}, and {@code TenantResolutionFilter} then ignores the tenant
 * and baseline headers entirely rather than checking them, so a forged value selects nothing
 * (see {@code docs/adr/0001}). Unset — a multi-tenant deployment — the header is still trusted
 * verbatim, and closing it remains an edge/ingress decision that nothing in this codebase makes.
 *
 * <p>Centralising the header name here (rather than the bare string literal previously
 * repeated at each {@code @HeaderParam}) is so this trust-boundary requirement is discoverable
 * from one place, not implied only by adapter-level prose — mirroring how
 * {@link TenantHeaders} documents the corresponding requirement — and its fixed-tenant way
 * out — for the tenant header.
 */
public final class SubjectHeaders {

    /** The authenticated end-user subject header. See the class javadoc for its trust boundary. */
    public static final String SUBJECT = "X-Subject-Id";

    private SubjectHeaders() {
    }
}
