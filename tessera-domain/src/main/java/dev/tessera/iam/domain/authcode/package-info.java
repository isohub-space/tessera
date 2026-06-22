/**
 * The Authorization Code + PKCE flow as pure domain logic.
 *
 * <p>This package models the protocol values and proofs of the OAuth 2.0 Authorization
 * Code grant with mandatory PKCE (RFC 6749 §4.1, RFC 7636) — the validated
 * {@link dev.tessera.iam.domain.authcode.AuthorizationRequest}, the single-use
 * {@link dev.tessera.iam.domain.authcode.AuthorizationGrant} bound to an issued code,
 * the {@link dev.tessera.iam.domain.authcode.CodeChallenge} / mandatory-S256
 * {@link dev.tessera.iam.domain.authcode.PkceMethod}, the pure constant-time
 * {@link dev.tessera.iam.domain.authcode.PkceVerifier}, the closed
 * {@link dev.tessera.iam.domain.authcode.AuthorizationError} code set, and the
 * {@link dev.tessera.iam.domain.authcode.IssuedTokenClaims} assembler that builds the
 * RFC 9068 access-token and OIDC ID-token claim sets.
 *
 * <p>Everything here is framework-free, immutable and side-effect-free: no clock, no
 * randomness, no I/O. Token signing, code generation/storage and the redirect/HTTP
 * mechanics are adapter concerns in the shell — the domain owns only the protocol
 * invariants, so they can be unit-tested without booting a container.
 */
package dev.tessera.iam.domain.authcode;
