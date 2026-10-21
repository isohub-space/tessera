package dev.tessera.iam.adapter.rest.problem;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A saturated credential verifier is answered 503 with Retry-After")
class CredentialVerificationBusyMapperTest {

    @Test
    @DisplayName("503 problem+json, Retry-After in whole seconds, never cached")
    void busyIsServiceUnavailable() {
        Response response = new CredentialVerificationBusyMapper().busy(new CredentialVerificationBusyException(2));

        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getMediaType().toString()).isEqualTo(ProblemResponse.MEDIA_TYPE);
        assertThat(response.getHeaderString("Retry-After")).isEqualTo("2");
        assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
        assertThat(((ProblemResponse) response.getEntity()).status()).isEqualTo(503);
    }
}
