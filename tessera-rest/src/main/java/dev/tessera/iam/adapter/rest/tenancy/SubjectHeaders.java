package dev.tessera.iam.adapter.rest.tenancy;

/**
 * The trusted ingress header contract for the authenticated end-user subject.
 *
 * <p><strong>Trust boundary — read this before deploying tessera as a public origin.</strong>
 * {@link #SUBJECT} ({@value #SUBJECT}) rests on exactly the same edge contract as
 * {@link TenantHeaders#TENANT}, and that contract is <strong>not enforced anywhere in
 * code</strong> for either header today: {@code TenantResolutionFilter} contains no trust
 * check at all — it resolves whatever is in {@code X-Tenant-Id} and binds it — and the same
 * is true here: {@link #SUBJECT} is populated either by an upstream authenticating proxy
 * that has already established the caller's identity, or (once wired) a verified session —
 * and in both cases the deployment's edge (gateway, load balancer, or equivalent ingress
 * component) <strong>must strip any client-supplied value for this header before the request
 * reaches this server</strong>. Both headers are stated as gateway-asserted only in prose
 * ({@code TenantHeaders}'s javadoc, and {@code AuthorizeResource}'s "an upstream
 * authenticating proxy" language for this one); a deployment that exposes either header to
 * callers whose edge does not strip client-supplied values is not a supported mode, but
 * nothing in this codebase currently makes that unsupported mode impossible to reach.
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
 * {@link TenantHeaders} documents the identical (and, for that header, still entirely
 * prose-only) requirement for the tenant header.
 */
public final class SubjectHeaders {

    /** The authenticated end-user subject header. See the class javadoc for its trust boundary. */
    public static final String SUBJECT = "X-Subject-Id";

    private SubjectHeaders() {
    }
}
