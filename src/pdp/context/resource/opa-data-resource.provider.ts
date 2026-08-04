import { Injectable, Logger } from '@nestjs/common';
import { readFileSync } from 'fs';
import { join } from 'path';
import { ResourceContext, ResourceRef } from '../../pdp.types';
import { ResourceProvider, ResourceResolution } from './resource-provider';

/**
 * Default resource provider. Resolves resources from the OPA policy data file
 * (opa/data/zta.json) so that OPA is the SINGLE SOURCE OF TRUTH for resource
 * inventory — the PDP and OPA read the same file, with no duplicated
 * mock-sources/resources.json to drift out of sync.
 *
 * Enabled with RESOURCE_MODE=opa-data (default). Path via OPA_DATA_FILE
 * (default: <cwd>/opa/data/zta.json; the file is baked into the PDP image).
 *
 * Only the authorization-relevant *identity* of a resource (type/criticality/
 * name) is surfaced here; required_mfa, max_risk_score and device requirements
 * stay inside OPA and are evaluated by zta.rego.
 */
interface OpaResourceEntry {
  type?: string;
  criticality?: string;
}

interface OpaData {
  enterprise?: { zta?: { resources?: Record<string, OpaResourceEntry> } };
}

@Injectable()
export class OpaDataResourceProvider implements ResourceProvider {
  readonly mode = 'opa-data' as const;

  private readonly logger = new Logger(OpaDataResourceProvider.name);
  private readonly filePath =
    process.env.OPA_DATA_FILE ?? join(process.cwd(), 'opa/data/zta.json');
  private readonly resources: Record<string, OpaResourceEntry>;

  constructor() {
    const raw = JSON.parse(readFileSync(this.filePath, 'utf8')) as OpaData;
    this.resources = raw.enterprise?.zta?.resources ?? {};
    this.logger.log(
      `OPA-data resource provider active (file=${this.filePath}, resources=${Object.keys(this.resources).length})`,
    );
  }

  async resolveResource(ref: ResourceRef): Promise<ResourceResolution> {
    const adapter = `opa-data:${this.filePath}`;
    const entry = this.resources[ref.resource_id];

    if (!entry) {
      // Unknown resource: no result. OPA also denies via `known_resource`, so
      // the decision fails closed either way.
      return {
        adapter,
        lookupKey: ref.resource_id,
        error: `Unknown resource "${ref.resource_id}"`,
      };
    }

    const resource: ResourceContext = {
      type: entry.type ?? '',
      name: ref.resource_id,
      criticality: entry.criticality ?? '',
    };

    return { resource, adapter, lookupKey: ref.resource_id };
  }
}
