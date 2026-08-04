import { SubjectContext, SubjectRef } from '../../pdp.types';

/**
 * Injection token for the active IdentityProvider implementation.
 * The concrete provider (mock or oidc) is selected at module wiring time
 * based on the IDENTITY_MODE environment variable.
 */
export const IDENTITY_PROVIDER = 'IDENTITY_PROVIDER';

/**
 * Result of resolving a subject reference into a canonical subject.
 *
 * `adapter` and `lookupKey` describe, for the audit trace, WHERE the identity
 * came from (mock file vs. real IdP) and WHICH key was used, without leaking
 * raw tokens.
 */
export interface IdentityResolution {
  subject?: SubjectContext;
  adapter: string;
  lookupKey: string;
  issuer?: string;
  error?: string;
}

/**
 * A source of subject identity. `mock` reads a local JSON file; `oidc`
 * verifies a real JWT against an Identity Provider's JWKS and maps claims.
 */
export interface IdentityProvider {
  readonly mode: 'mock' | 'oidc';
  resolveSubject(ref: SubjectRef): Promise<IdentityResolution>;
}
