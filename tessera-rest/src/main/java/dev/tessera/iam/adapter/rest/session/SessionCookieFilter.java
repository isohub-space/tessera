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
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

/**
 * Fills the {@code X-Subject-Id} seam from the session cookie, for any tenant-scoped request
 * that does not already carry the header.
 *
 * <p>This is the piece IAM-49 AC2 calls for: {@code AuthorizeResource} (and any other
 * tenant-scoped endpoint) keeps reading the authenticated subject from
 * {@code X-Subject-Id} exactly as before — that seam is untouched — and this filter is what
 * now sits upstream of it, translating an established session cookie into that header
 * <em>before</em> the resource method runs, playing the role its javadoc describes for "an
 * upstream authenticating proxy". A request that already carries {@code X-Subject-Id}
 * (e.g. a gateway that authenticates independently) is left alone: this filter never
 * overrides an explicitly asserted subject.
 *
 * <p><strong>This filter does NOT strip a client-supplied {@code X-Subject-Id} — it only ever
 * ADDS one when absent.</strong> See {@link SubjectHeaders} for why that header must never
 * reach this server from an untrusted caller in the first place: this filter fills the seam
 * for the legitimate case (a real session cookie, no header yet), it is not, and cannot be, a
 * defence against a forged header arriving alongside — or instead of — a cookie. That defence
 * has to live at the network edge, not here.
 *
 * <p>Runs after {@code TenantResolutionFilter} ({@link Priorities#AUTHENTICATION}) so the
 * realm is bound, and before {@code RateLimitFilter} ({@code AUTHENTICATION + 100}). Skips
 * silently (never a 4xx) whenever there is nothing to translate: no tenant bound, no cookie,
 * a malformed cookie value, or a cookie that does not resolve to a live session — the
 * downstream resource's own {@code X-Subject-Id}-blank handling is what turns "no subject"
 * into the right protocol error.
 */
@Singleton
public class SessionCookieFilter {

    @Inject
    TenantContext tenantContext;

    @Inject
    SessionUseCase sessions;

    @ServerRequestFilter(priority = Priorities.AUTHENTICATION + 10)
    public Uni<Void> filter(ContainerRequestContext request) {
        if (request.getHeaderString(SubjectHeaders.SUBJECT) != null) {
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
