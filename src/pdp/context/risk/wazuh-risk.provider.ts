import { Injectable, Logger } from '@nestjs/common';
import { RiskContext } from '../../pdp.types';
import { WazuhClient } from '../wazuh/wazuh-client';
import { RiskProvider, RiskResolution } from './risk-provider';

/**
 * Real risk provider. Derives siem_score from the highest Wazuh alert rule.level
 * seen for the request source IP in the recent window (default 24h). Wazuh alert
 * levels run 0-16; they are scaled to a 0-100 score.
 *
 * Enabled with RISK_MODE=wazuh. threat_intel_match / impossible_travel are left
 * false here (MISP supplies threat_intel via the composite provider). Fail-closed
 * by default: any Wazuh error yields siem_score 100 so OPA denies, unless
 * WAZUH_FAIL_OPEN=true.
 */
@Injectable()
export class WazuhRiskProvider implements RiskProvider {
  readonly mode = 'wazuh' as const;

  private readonly logger = new Logger(WazuhRiskProvider.name);
  private readonly client = new WazuhClient();
  private readonly failOpen = process.env.WAZUH_FAIL_OPEN === 'true';

  async resolveRisk(sourceIp: string | undefined): Promise<RiskResolution> {
    const adapter = `wazuh:${this.client.indexerUrl}`;
    const benign: RiskContext = {
      siem_score: 0,
      threat_intel_match: false,
      impossible_travel: false,
    };

    if (!sourceIp) {
      return { risk: benign, adapter, lookupKey: 'no-source-ip' };
    }

    try {
      const maxLevel = await this.client.maxAlertLevel({ ip: sourceIp });
      const siem_score = this.scoreFromLevel(maxLevel);

      return {
        risk: { siem_score, threat_intel_match: false, impossible_travel: false },
        adapter,
        lookupKey: sourceIp,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Wazuh risk lookup failed for ${sourceIp}: ${message}`);

      const risk: RiskContext = this.failOpen
        ? benign
        : { siem_score: 100, threat_intel_match: false, impossible_travel: false };

      return {
        risk,
        adapter,
        lookupKey: sourceIp,
        error: `Wazuh risk lookup failed (${this.failOpen ? 'fail-open' : 'fail-closed'}): ${message}`,
      };
    }
  }

  /** Scale a Wazuh rule.level (0-16) to a 0-100 score. */
  private scoreFromLevel(level: number): number {
    const clamped = Math.max(0, Math.min(16, level));
    return Math.min(100, Math.round((clamped / 15) * 100));
  }
}
