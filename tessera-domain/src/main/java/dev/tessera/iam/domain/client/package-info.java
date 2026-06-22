/**
 * Client model for the Tessera domain.
 *
 * <p>Replaces Keycloak's mutable {@code ClientModel} with an immutable sealed
 * pair: {@link dev.tessera.iam.domain.client.ConfidentialClient} (authenticates via a
 * {@link dev.tessera.iam.domain.client.ClientAuthMethod}, no {@code NONE}) and
 * {@link dev.tessera.iam.domain.client.PublicClient} (PKCE-S256 + DPoP by
 * construction, no secret field). Both carry a defensively-copied, unmodifiable
 * set of permitted {@link dev.tessera.iam.domain.client.grant.GrantType}s and a
 * {@link dev.tessera.iam.domain.tenancy.RealmKey}.
 */
package dev.tessera.iam.domain.client;
