/**
 * The token signing-key domain: algorithm model, key identity and public JWK shape,
 * and the pure four-state rotation policy.
 *
 * <p>Framework-free functional core. It owns the <em>rules</em> of key rotation —
 * the legal lifecycle PENDING&rarr;ACTIVE&rarr;RETIRING&rarr;RETIRED,
 * publish-before-sign, retire-after-max-TTL (with the clock injected by the caller),
 * JWKS publication and key selection — but holds no private key bytes and performs no
 * cryptography. Key generation, signing and JWK encoding live entirely in the adapter
 * shell.
 */
package dev.tessera.iam.domain.signingkey;
