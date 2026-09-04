package dev.tessera.iam.adapter.rest.tenancy;

/**
 * The trusted ingress header contract for the authenticated end-user subject.
 *
 * <p><strong>Trust boundary — read this before deploying tessera as a public origin.</strong>
 * {@link #SUBJECT} ({@value #SUBJECT}) carries exactly the same trust requirement as
 * {@link TenantHeaders#TENANT}: it is populated either by {@link
 * dev.tessera.iam.adapter.rest.session.SessionCookieFilter} (from a verified session) or by
 * an upstream authenticating proxy that has already established the caller's identity — and
 * in both cases, the deployment's edge (gateway, load balancer, or equivalent ingress
 * component) <strong>must strip any client-supplied value for this header before the request
 * reaches this server</strong>, exactly as it must for {@code X-Tenant-Id}.
 *
 * <p><strong>This is not merely a convention — it is the entire authentication boundary for
 * every endpoint that reads it</strong> ({@code /authorize}, {@code /consent}): unlike
 * {@code X-Tenant-Id}, this value is an opaque, unparsed string with no format to validate, so
 * there is no code-level check that could ever distinguish a genuine upstream-asserted value
 * from one a caller fabricated by simply setting the header on a direct HTTP request — tessera
 * cannot tell the two apart once both reach the JAX-RS layer over the same connection. If a
 * deployment exposes tessera to callers who are not behind an edge that scrubs this header
 * (for example, a standalone public Cloud Run origin with no such stripping rule configured),
 * {@code X-Subject-Id} becomes a complete, trivial authentication bypass: any caller can set
 * {@code X-Subject-Id: <victim-sub>} and be treated as that user with no credential at all.
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
