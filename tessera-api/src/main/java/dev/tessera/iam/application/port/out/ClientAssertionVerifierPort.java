// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application.port.out;

import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Outbound port that verifies a JWT client assertion (RFC 7523 §3) against a client's
 * {@link AssertionTrust}: the signature with an allowed asymmetric algorithm, {@code iss},
 * {@code sub}, {@code aud}, the validity window, and single use of its {@code jti}.
 *
 * <p>Every check fails closed, and a failure never says which check it was. With no trust (an
 * unknown client, or one registered for another method) the adapter still verifies the signature,
 * against a key no client holds, so a refusal costs the same whatever its cause.
 */
public interface ClientAssertionVerifierPort {

    /**
     * @param realm     the realm the request runs within; it scopes {@code jti} replay
     * @param trust     what the assertion must match, or {@code null} to run a failing check
     * @param assertion the presented {@code client_assertion}
     * @param budget    the endpoint family whose replay budget a newly spent {@code jti} counts
     *                  against; the {@code jti} itself is spent for every endpoint alike
     * @return a {@link Uni} emitting {@code true} only when every check passes and the {@code jti}
     *         has not been used before, at any endpoint
     */
    Uni<Boolean> verify(RealmKey realm, AssertionTrust trust, String assertion, ReplayBudget budget);

    /**
     * Which bound a newly spent {@code jti} counts against. There is one {@code jti} namespace, so an
     * assertion spent at one endpoint is refused at every other; only the caps are separate. A
     * resource server introspecting with an assertion spends one {@code jti} per call, and how often
     * it calls is driven by the tokens its own callers present, so that load must never use up the
     * budget the same client needs to obtain its tokens.
     */
    enum ReplayBudget {
        /** {@code /token}: the {@code client_credentials} grant. */
        TOKEN,
        /** {@code /introspect} and {@code /revoke}. */
        INTROSPECTION_AND_REVOCATION
    }
}
