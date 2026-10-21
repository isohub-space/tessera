package dev.tessera.iam.adapter.rest.problem;

import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * Answers a request refused because credential verification is saturated with {@code 503} and
 * {@code Retry-After}, on every endpoint that verifies a credential. It is not an OAuth error: the
 * client's credentials were never examined, so neither {@code invalid_client} nor a spent failure
 * budget would be true.
 */
public class CredentialVerificationBusyMapper {

    @ServerExceptionMapper
    public Response busy(CredentialVerificationBusyException busy) {
        return ProblemResponse.serviceUnavailable(busy.retryAfterSeconds());
    }
}
