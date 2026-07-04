package dev.tessera.iam.adapter.rest.problem;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.ws.rs.core.Response;

/**
 * RFC 7807 Problem Details body, served as {@code application/problem+json}.
 *
 * @param type   URI reference identifying the problem type ({@code about:blank} default)
 * @param title  short, human-readable summary
 * @param status HTTP status code
 * @param detail human-readable explanation of this occurrence
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ProblemResponse(String type, String title, int status, String detail) {

    /** MIME type for RFC 7807 responses. */
    public static final String MEDIA_TYPE = "application/problem+json";

    /** Builds a 404 problem response for an unknown item. */
    public static Response notFound(String id) {
        ProblemResponse body =
                new ProblemResponse(
                        "about:blank",
                        "Item Not Found",
                        Response.Status.NOT_FOUND.getStatusCode(),
                        "No item exists with id: " + id);
        return Response.status(Response.Status.NOT_FOUND).type(MEDIA_TYPE).entity(body).build();
    }

    /** Builds a 400 problem response for a malformed request parameter. */
    public static Response badRequest(String detail) {
        ProblemResponse body =
                new ProblemResponse(
                        "about:blank",
                        "Bad Request",
                        Response.Status.BAD_REQUEST.getStatusCode(),
                        detail);
        return Response.status(Response.Status.BAD_REQUEST).type(MEDIA_TYPE).entity(body).build();
    }

    /**
     * Builds a 429 problem response for a throttled request. Carries {@code Retry-After} (whole
     * seconds, per RFC 7231) so the caller can back off, and {@code Cache-Control: no-store} so the
     * throttling verdict is never cached.
     */
    public static Response tooManyRequests(long retryAfterSeconds) {
        ProblemResponse body =
                new ProblemResponse(
                        "about:blank",
                        "Too Many Requests",
                        429,
                        "Request rate exceeded; retry after " + retryAfterSeconds + " seconds.");
        return Response.status(429)
                .type(MEDIA_TYPE)
                .header("Retry-After", Long.toString(Math.max(0L, retryAfterSeconds)))
                .header("Cache-Control", "no-store")
                .entity(body)
                .build();
    }
}
