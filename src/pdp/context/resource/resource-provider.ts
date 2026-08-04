import { ResourceContext, ResourceRef } from '../../pdp.types';

/**
 * Injection token for the active ResourceProvider implementation, selected at
 * module wiring time from the RESOURCE_MODE environment variable.
 */
export const RESOURCE_PROVIDER = 'RESOURCE_PROVIDER';

/**
 * Result of resolving a resource reference into the canonical resource context.
 * `adapter` and `lookupKey` describe, for the audit trace, WHERE the resource
 * inventory came from and WHICH key was used.
 */
export interface ResourceResolution {
  resource?: ResourceContext;
  adapter: string;
  lookupKey: string;
  error?: string;
}

/**
 * A source of resource inventory. `opa-data` (default) reads the OPA policy data
 * file so OPA is the single source of truth; `mock` reads a local JSON file.
 */
export interface ResourceProvider {
  readonly mode: 'mock' | 'opa-data';
  resolveResource(ref: ResourceRef): Promise<ResourceResolution>;
}
