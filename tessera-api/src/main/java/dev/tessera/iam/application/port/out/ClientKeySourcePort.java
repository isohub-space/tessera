// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Outbound port that resolves what a client's JWT assertions (RFC 7523) are verified against: the
 * public keys and the {@code iss} and {@code sub} the assertion must carry.
 *
 * <p>This is the one place a key source plugs in. For {@code private_key_jwt} the keys are the
 * client's registered JWKS and both {@code iss} and {@code sub} are its {@code client_id}. For a
 * client of a trusted external issuer (a platform's workload identity) the trust names the
 * registered issuer and subject and carries no keys: the verifier takes them from the issuer, so
 * the verification path stays the same.
 *
 * <p>Like {@link ClientSecretVerifierPort}, it is called on every assertion request, for an
 * unknown client with the {@link ClientSecretVerifierPort#unknownClient sentinel} id, so the
 * lookup costs the same whether or not the client exists.
 */
public interface ClientKeySourcePort {

    /**
     * @param realm    the realm the client belongs to (RLS-scoped)
     * @param clientId the resolved client identity, or a sentinel
     * @return a {@link Uni} emitting the client's assertion trust, or {@code null} when the client
     *         is unknown or not registered for assertion authentication
     */
    Uni<AssertionTrust> trustFor(RealmKey realm, ClientId clientId);

    /**
     * What one client's assertions must match.
     *
     * @param issuer  the {@code iss} the assertion must carry
     * @param subject the {@code sub} the assertion must carry
     * @param jwks    the JWK Set (RFC 7517) JSON holding the public keys it may be signed with, or
     *                {@code null} for a client of a trusted external issuer, whose keys are the issuer's
     */
    record AssertionTrust(String issuer, String subject, String jwks) {

        public AssertionTrust {
            if (issuer == null || issuer.isBlank() || subject == null || subject.isBlank()
                    || (jwks != null && jwks.isBlank())) {
                throw new IllegalArgumentException("AssertionTrust issuer and subject, and jwks if given, must not be blank");
            }
        }

        /** The trust of a client of a trusted external issuer: the issuer's keys apply. */
        public static AssertionTrust ofIssuer(String issuer, String subject) {
            return new AssertionTrust(issuer, subject, null);
        }
    }
}
