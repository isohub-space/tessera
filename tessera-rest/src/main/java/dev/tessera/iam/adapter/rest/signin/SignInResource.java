// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import dev.tessera.iam.adapter.rest.AuthorizationResponses;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.adapter.rest.login.LoginConfig;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimited;
import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import dev.tessera.iam.adapter.rest.tenancy.TenantScoped;
import dev.tessera.iam.application.port.in.SignInUseCase;
import dev.tessera.iam.application.port.in.SignInUseCase.Form;
import dev.tessera.iam.application.port.in.SignInUseCase.FormResult;
import dev.tessera.iam.application.port.in.SignInUseCase.Submission;
import dev.tessera.iam.application.port.in.SignInUseCase.SubmitResult;
import io.quarkus.qute.TemplateInstance;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * tessera's hosted sign-in page ({@code GET} and {@code POST /signin}).
 *
 * <p>{@code /authorize} sends a browser here when the request it validated carries no signed-in
 * user: {@code 303 /signin?txn=…}, with the binding cookie ({@link SignInCookies}). This page
 * shows the form, takes the password on tessera's own origin, and on success answers the
 * parked request with {@code 303} to the client's registered redirect URI carrying
 * {@code code}, {@code state} and {@code iss}. A client therefore never sees the password and
 * needs no form of its own, whatever site it runs on.
 *
 * <p>A post is accepted only when it carries the binding cookie and the form's synchronizer
 * token, and, when the browser says where it came from, {@code Sec-Fetch-Site: same-origin}.
 * Where the redirect goes is never read from the post: it is the redirect URI validated when
 * the request was parked.
 *
 * <p>Every response is {@code no-store} and carries the page's own Content-Security-Policy
 * ({@link SignInPagePolicy}); the server-wide policy is configured to skip this path.
 */
@Path("/signin")
@Tag(name = "sign-in", description = "Hosted sign-in page for the authorization code flow.")
@TenantScoped
@RateLimited
public class SignInResource {

    private static final String HTML = MediaType.TEXT_HTML + ";charset=UTF-8";
    private static final String SAME_ORIGIN = "same-origin";

    @Inject
    SignInUseCase signIn;

    @Inject
    TenantContext tenantContext;

    @Inject
    OidcDiscoveryConfig oidc;

    @Inject
    LoginConfig login;

    /** The sign-in form ({@code templates/SignInResource/signin.html}). */
    record signin(String transactionId, String csrfToken, boolean failed) implements TemplateInstance {
    }

    /** The page for a sign-in that cannot continue ({@code templates/SignInResource/unavailable.html}). */
    record unavailable() implements TemplateInstance {
    }

    @GET
    @Produces(MediaType.TEXT_HTML)
    @Operation(operationId = "signInPage", summary = "Show the sign-in form for a pending authorization request")
    public Uni<Response> show(
            @QueryParam("txn") String transactionId, @CookieParam(SignInCookies.NAME) String binding) {
        return signIn.show(tenantContext.realm(), transactionId, binding)
                .map(result -> switch (result) {
                    case FormResult.Shown shown -> form(Response.Status.OK, shown.form(), false);
                    case FormResult.Unavailable unavailable -> unavailable(Response.Status.BAD_REQUEST);
                });
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    @Operation(operationId = "signIn", summary = "Sign in and answer the pending authorization request")
    public Uni<Response> submit(
            @Context UriInfo uriInfo,
            @HeaderParam("Sec-Fetch-Site") String fetchSite,
            @CookieParam(SignInCookies.NAME) String binding,
            @FormParam("txn") String transactionId,
            @FormParam("csrf") String csrfToken,
            @FormParam("username") String username,
            @FormParam("password") String password) {
        // Browsers that send Fetch Metadata say where a post came from; only this page's own
        // form may post here. One that sends none still has to carry the synchronizer token.
        if (fetchSite != null && !SAME_ORIGIN.equals(fetchSite)) {
            return Uni.createFrom().item(unavailable(Response.Status.FORBIDDEN));
        }
        Submission submission = new Submission(
                tenantContext.realm(), transactionId, binding, csrfToken, username, password);
        return signIn.submit(submission).map(result -> switch (result) {
            case SubmitResult.Completed completed -> Response.seeOther(AuthorizationResponses.success(
                            completed.redirectUri(), completed.code(), completed.state(), oidc.issuer()))
                    .cookie(SessionCookies.issue(
                                    completed.sessionId().toString(), login.sessionTtl().toSeconds()),
                            SignInCookies.clear(uriInfo))
                    .header("Cache-Control", "no-store")
                    .build();
            case SubmitResult.Denied denied -> form(Response.Status.UNAUTHORIZED, denied.form(), true);
            case SubmitResult.Unavailable unavailable -> unavailable(Response.Status.BAD_REQUEST);
            case SubmitResult.Refused refused -> unavailable(Response.Status.BAD_REQUEST);
        });
    }

    private static Response form(Response.Status status, Form form, boolean failed) {
        return page(status,
                new signin(form.transactionId(), form.csrfToken(), failed).render(),
                SignInPagePolicy.form(form.redirectUri()));
    }

    private static Response unavailable(Response.Status status) {
        return page(status, new unavailable().render(), SignInPagePolicy.closed());
    }

    private static Response page(Response.Status status, String body, String policy) {
        return Response.status(status)
                .type(HTML)
                .entity(body)
                .header("Content-Security-Policy", policy)
                .header("Cache-Control", "no-store")
                .build();
    }
}
