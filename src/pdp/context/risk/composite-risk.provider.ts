import { Injectable } from '@nestjs/common';
import { RiskContext } from '../../pdp.types';
import { RiskProvider, RiskResolution } from './risk-provider';
import { WazuhRiskProvider } from './wazuh-risk.provider';
import { MispRiskProvider } from './misp-risk.provider';

/**
 * Composite risk provider (RISK_MODE=wazuh-misp). Queries both real risk sources
 * for the source IP and merges them:
 *   siem_score         = max(Wazuh SIEM score, MISP-derived score)
 *   threat_intel_match = MISP hit
 *   impossible_travel  = either source (both currently false)
 *
 * Taking the MAX of the two scores preserves each provider's fail-closed
 * behaviour: if either sub-provider errors it returns siem_score 100, which
 * dominates the max and makes OPA deny.
 */
@Injectable()
export class CompositeRiskProvider implements RiskProvider {
  readonly mode = 'wazuh' as const; // mock/misp/wazuh union; composite reports wazuh

  private readonly wazuh = new WazuhRiskProvider();
  private readonly misp = new MispRiskProvider();

  private readonly deny: RiskContext = {
    siem_score: 100,
    threat_intel_match: false,
    impossible_travel: false,
  };

  async resolveRisk(sourceIp: string | undefined): Promise<RiskResolution> {
    const [w, m] = await Promise.all([
      this.wazuh.resolveRisk(sourceIp),
      this.misp.resolveRisk(sourceIp),
    ]);

    const wr = w.risk ?? this.deny;
    const mr = m.risk ?? this.deny;

    const risk: RiskContext = {
      siem_score: Math.max(wr.siem_score, mr.siem_score),
      threat_intel_match: wr.threat_intel_match || mr.threat_intel_match,
      impossible_travel: wr.impossible_travel || mr.impossible_travel,
    };

    const errors = [w.error, m.error].filter(Boolean);

    return {
      risk,
      adapter: `wazuh-misp(${w.adapter} + ${m.adapter})`,
      lookupKey: sourceIp ?? 'default',
      error: errors.length > 0 ? errors.join('; ') : undefined,
    };
  }
}
