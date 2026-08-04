import { Logger, Provider } from '@nestjs/common';
import { MockSourceRepository } from '../mock-source.repository';
import { RISK_PROVIDER, RiskProvider } from './risk-provider';
import { MockRiskProvider } from './mock-risk.provider';
import { MispRiskProvider } from './misp-risk.provider';
import { WazuhRiskProvider } from './wazuh-risk.provider';
import { CompositeRiskProvider } from './composite-risk.provider';

/**
 * Selects the risk provider from RISK_MODE:
 *   mock (default) -> local mock-sources/risks.json
 *   misp           -> live MISP threat-intel lookup by source IP
 *   wazuh          -> Wazuh SIEM score by source IP
 *   wazuh-misp     -> composite: Wazuh SIEM score + MISP threat-intel
 */
export const riskProviderFactory: Provider = {
  provide: RISK_PROVIDER,
  inject: [MockSourceRepository],
  useFactory: (sources: MockSourceRepository): RiskProvider => {
    const mode = (process.env.RISK_MODE ?? 'mock').toLowerCase();
    const logger = new Logger('RiskProviderFactory');

    if (mode === 'wazuh-misp') {
      logger.log('RISK_MODE=wazuh-misp -> composite Wazuh SIEM + MISP threat-intel');
      return new CompositeRiskProvider();
    }

    if (mode === 'wazuh') {
      logger.log('RISK_MODE=wazuh -> using Wazuh SIEM risk provider');
      return new WazuhRiskProvider();
    }

    if (mode === 'misp') {
      logger.log('RISK_MODE=misp -> using live MISP threat-intel risk provider');
      return new MispRiskProvider();
    }

    if (mode !== 'mock') {
      throw new Error(
        `Unsupported RISK_MODE="${mode}" (expected mock, misp, wazuh, or wazuh-misp)`,
      );
    }

    return new MockRiskProvider(sources);
  },
};
