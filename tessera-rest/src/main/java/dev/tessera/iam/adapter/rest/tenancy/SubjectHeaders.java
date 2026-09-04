package dev.tessera.iam.adapter.rest.tenancy;

/**
 * The trusted ingress header contract for the authenticated end-user subject.
 *
 * <p><strong>Trust boundary — read this before deploying tessera as a public origin.</strong>
 * {@link #SUBJECT} ({@value #SUBJECT}) rests on exactly the same edge contract as
 * {@link TenantHeaders#TENANT}, and that contract is <strong>not enforced anywhere in
 * code</strong> for either header: {@code TenantResolutionFilter} contains no trust check at
 * all — it resolves whatever is in {@code X-Tenant-Id} and binds it — and, absent the filter
 * below, the same would be true here. Both headers are stated as gateway-asserted only in
 * prose ({@code TenantHeaders}'s javadoc, and {@code AuthorizeResource}'s "an upstream
 * authenticating proxy" language for this one); a deployment that exposes either header to
 * callers whose edge does not strip client-supplied values is not a supported mode, but
 * nothing in this codebase makes that unsupported mode impossible to reach.
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
 * {@code X-Tenant-Id} has no equivalent application-layer check: on a standalone public
 * origin, a forged tenant header is exactly as live a risk as a forged subject header was
 * before this filter existed, and closing it (if closed at all) is an edge/ingress decision,
 * not something this class or {@code TenantResolutionFilter} currently does.
 *
 * <p>Centralising the header name here (rather than the bare string literal previously
 * repeated at each {@code @HeaderParam}) is so this trust-boundary requirement is discoverable
 * from one place, not implied only by adapter-level prose — mirroring how
 * {@link TenantHeaders} documents the identical (and, for that header, still entirely
 * prose-only) requirement for the tenant header.
 */
public final class SubjectHeaders {

    /** The authenticated end-user subject header. See the class javadoc for its trust boundary. */
    public static final String SUBJECT = "X-Subject-Id";

    private SubjectHeaders() {
    }
}
