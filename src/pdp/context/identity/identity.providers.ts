import { Logger, Provider } from '@nestjs/common';
import { MockSourceRepository } from '../mock-source.repository';
import { IDENTITY_PROVIDER, IdentityProvider } from './identity-provider';
import { MockIdentityProvider } from './mock-identity.provider';
import { OidcIdentityProvider } from './oidc-identity.provider';

/**
 * Selects the identity provider from IDENTITY_MODE:
 *   mock (default) -> local mock-sources/identity.json
 *   oidc           -> real JWT verified against an IdP's JWKS
 */
export const identityProviderFactory: Provider = {
  provide: IDENTITY_PROVIDER,
  inject: [MockSourceRepository],
  useFactory: (sources: MockSourceRepository): IdentityProvider => {
    const mode = (process.env.IDENTITY_MODE ?? 'mock').toLowerCase();
    const logger = new Logger('IdentityProviderFactory');

    if (mode === 'oidc') {
      logger.log('IDENTITY_MODE=oidc -> using real OIDC/JWT identity provider');
      return new OidcIdentityProvider();
    }

    if (mode !== 'mock') {
      logger.warn(
        `Unknown IDENTITY_MODE="${mode}", falling back to mock identity provider`,
      );
    }

    return new MockIdentityProvider(sources);
  },
};
