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
     * @return a {@link Uni} emitting {@code true} only when every check passes and the {@code jti}
     *         has not been used before
     */
    Uni<Boolean> verify(RealmKey realm, AssertionTrust trust, String assertion);
}
