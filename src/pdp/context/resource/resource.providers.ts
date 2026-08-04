import { Logger, Provider } from '@nestjs/common';
import { MockSourceRepository } from '../mock-source.repository';
import { RESOURCE_PROVIDER, ResourceProvider } from './resource-provider';
import { MockResourceProvider } from './mock-resource.provider';
import { OpaDataResourceProvider } from './opa-data-resource.provider';

/**
 * Selects the resource provider from RESOURCE_MODE:
 *   opa-data (default) -> resources read from opa/data/zta.json (OPA is truth)
 *   mock               -> local mock-sources/resources.json (test/dev only)
 */
export const resourceProviderFactory: Provider = {
  provide: RESOURCE_PROVIDER,
  inject: [MockSourceRepository],
  useFactory: (sources: MockSourceRepository): ResourceProvider => {
    const mode = (process.env.RESOURCE_MODE ?? 'opa-data').toLowerCase();
    const logger = new Logger('ResourceProviderFactory');

    if (mode === 'mock') {
      logger.log('RESOURCE_MODE=mock -> using mock-sources/resources.json');
      return new MockResourceProvider(sources);
    }

    if (mode !== 'opa-data') {
      throw new Error(
        `Unsupported RESOURCE_MODE="${mode}" (expected mock or opa-data)`,
      );
    }

    return new OpaDataResourceProvider();
  },
};
