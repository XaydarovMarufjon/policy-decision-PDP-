import { Injectable } from '@nestjs/common';
import { MockSourceRepository } from '../mock-source.repository';
import { RiskProvider, RiskResolution } from './risk-provider';

/**
 * Default risk provider. Resolves the risk context from the local
 * mock-sources/risks.json file. Used when RISK_MODE=mock (default).
 */
@Injectable()
export class MockRiskProvider implements RiskProvider {
  readonly mode = 'mock' as const;

  constructor(private readonly sources: MockSourceRepository) {}

  async resolveRisk(sourceIp: string | undefined): Promise<RiskResolution> {
    return {
      risk: this.sources.resolveRisk(sourceIp),
      adapter: 'mock-sources/risks.json',
      lookupKey: sourceIp ?? 'default',
    };
  }
}
