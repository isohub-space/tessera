package dev.tessera.iam.adapter.rest.tenancy;

/**
 * The trusted ingress header contract for the authenticated end-user subject.
 *
 * <p><strong>Trust boundary — read this before deploying tessera as a public origin.</strong>
 * {@link #SUBJECT} ({@value #SUBJECT}) carries the same trust requirement as
 * {@link TenantHeaders#TENANT}, with one difference: unlike the tenant header, this value is an
 * opaque, unparsed string with no format to validate, so a network edge that fails to strip a
 * client-supplied value is not the only line of defence. {@link
 * dev.tessera.iam.adapter.rest.session.SessionCookieFilter} enforces this at the application
 * layer too, <strong>default-closed</strong>: unless a deployment explicitly sets
 * {@code iam.subject.trust-header=true}, any inbound value for this header is stripped before
 * anything reads it, and a verified session cookie is the only remaining way to establish a
 * subject. Setting that flag is how a deployment opts into the older "upstream authenticating
 * proxy injects this header directly" mode {@code AuthorizeResource}'s javadoc documents — and
 * doing so is exactly as consequential as it sounds: with it set, tessera again trusts this
 * header verbatim, so the deployment's own edge (gateway, load balancer, or equivalent) MUST
 * strip any client-supplied value before the request reaches this server, or
 * {@code X-Subject-Id} becomes a complete, trivial authentication bypass — any caller sets
 * {@code X-Subject-Id: <victim-sub>} and is treated as that user with no credential at all.
 *
 * <p>Centralising the header name here (rather than the bare string literal previously
 * repeated at each {@code @HeaderParam}) is so this trust-boundary requirement is discoverable
 * from one place, not implied only by adapter-level prose — mirroring how
 * {@link TenantHeaders} documents the identical requirement for the tenant header.
 */
public final class SubjectHeaders {

    /** The authenticated end-user subject header. See the class javadoc for its trust boundary. */
    public static final String SUBJECT = "X-Subject-Id";

    private SubjectHeaders() {
    }
}
