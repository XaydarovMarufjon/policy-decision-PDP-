import { Injectable } from '@nestjs/common';
import { ResourceRef } from '../../pdp.types';
import { MockSourceRepository } from '../mock-source.repository';
import { ResourceProvider, ResourceResolution } from './resource-provider';

/**
 * Test/dev resource provider. Resolves resources from the local
 * mock-sources/resources.json file. Used when RESOURCE_MODE=mock; the default
 * is opa-data (OpaDataResourceProvider).
 */
@Injectable()
export class MockResourceProvider implements ResourceProvider {
  readonly mode = 'mock' as const;

  constructor(private readonly sources: MockSourceRepository) {}

  async resolveResource(ref: ResourceRef): Promise<ResourceResolution> {
    return {
      resource: this.sources.resolveResource(ref.resource_id),
      adapter: 'mock-sources/resources.json',
      lookupKey: ref.resource_id,
    };
  }
}
