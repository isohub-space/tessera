package dev.tessera.iam.adapter.rest.session;

import dev.tessera.iam.adapter.rest.tenancy.SubjectHeaders;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.application.port.in.SessionUseCase;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Cookie;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

/**
 * Establishes the {@code X-Subject-Id} seam for every tenant-scoped request — the single place
 * that decides what subject, if any, {@code AuthorizeResource} and {@code ConsentResource} will
 * see — and is the enforcement point for {@link SubjectHeaders}'s trust boundary.
 *
 * <p><strong>Default-closed.</strong> Unless {@code iam.subject.trust-header} is explicitly set
 * to {@code true}, ANY inbound {@code X-Subject-Id} presented by the caller is stripped before
 * anything else runs, and the ONLY way to establish a subject is a verified session cookie. This
 * is deliberately not "trust it unless something strips it at the edge": tessera cannot verify
 * that an edge strips it, so the safe default assumes it does not. A deployment that genuinely
 * relies on an upstream authenticating proxy injecting this header directly (the mode
 * {@code AuthorizeResource}'s javadoc originally documented) must opt in explicitly — the same
 * "decided explicitly, not defaulted" discipline this codebase applies to session-cookie flags,
 * rate limits and the signing-key master key.
 *
 * <p>This is the seam-filling piece the login flow needs: {@code AuthorizeResource} (and any other
 * tenant-scoped endpoint) keeps reading the authenticated subject from {@code X-Subject-Id}
 * exactly as before — that seam is untouched — and this filter is what now sits upstream of it,
 * translating an established session cookie into that header <em>before</em> the resource method
 * runs.
 *
 * <p>Runs after {@code TenantResolutionFilter} ({@link Priorities#AUTHENTICATION}) so the realm
 * is bound, and before {@code RateLimitFilter} ({@code AUTHENTICATION + 100}). Skips silently
 * (never a 4xx) whenever there is nothing to translate: no tenant bound, no cookie, a malformed
 * cookie value, or a cookie that does not resolve to a live session — the downstream resource's
 * own {@code X-Subject-Id}-blank handling is what turns "no subject" into the right protocol
 * error.
 */
@Singleton
public class SessionCookieFilter {

    @Inject
    TenantContext tenantContext;

    @Inject
    SessionUseCase sessions;

    /**
     * Trusted-edge escape hatch, default-closed. {@code true} only in a deployment that has
     * verified its own ingress asserts {@code X-Subject-Id} and strips any client-supplied
     * value before forwarding — tessera has no way to verify that itself, so it does not assume
     * it by default.
     */
    @ConfigProperty(name = "iam.subject.trust-header", defaultValue = "false")
    boolean trustHeader;

    @ServerRequestFilter(priority = Priorities.AUTHENTICATION + 10)
    public Uni<Void> filter(ContainerRequestContext request) {
        boolean callerSuppliedSubject = request.getHeaderString(SubjectHeaders.SUBJECT) != null;
        if (callerSuppliedSubject && !trustHeader) {
            // Default-closed: never trust a caller-presented value unless the deployment has
            // explicitly opted into trusted-edge mode. Strip it so it cannot reach the resource
            // as if it were absent — a session cookie is the only remaining path to a subject.
            request.getHeaders().remove(SubjectHeaders.SUBJECT);
            callerSuppliedSubject = false;
        }
        if (callerSuppliedSubject) {
            // Trusted-edge mode: an upstream authenticating proxy already asserted this, and
            // the deployment has confirmed its ingress strips any client-supplied value.
            return Uni.createFrom().voidItem();
        }
        Optional<RealmKey> realm = tenantContext.realmIfPresent();
        if (realm.isEmpty()) {
            return Uni.createFrom().voidItem();
        }
        Cookie cookie = request.getCookies().get(SessionCookies.NAME);
        if (cookie == null || cookie.getValue() == null || cookie.getValue().isBlank()) {
            return Uni.createFrom().voidItem();
        }
        SessionId sessionId;
        try {
            sessionId = SessionId.fromString(cookie.getValue());
        } catch (IllegalArgumentException malformed) {
            return Uni.createFrom().voidItem();
        }
        return sessions.resolveSubject(realm.get(), sessionId)
                .invoke(subject -> subject.ifPresent(
                        sub -> request.getHeaders().putSingle(SubjectHeaders.SUBJECT, sub)))
                .replaceWithVoid();
    }
}
