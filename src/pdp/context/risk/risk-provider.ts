import { RiskContext } from '../../pdp.types';

/**
 * Injection token for the active RiskProvider implementation, selected at
 * module wiring time from the RISK_MODE environment variable.
 */
export const RISK_PROVIDER = 'RISK_PROVIDER';

/**
 * Result of resolving the risk context for a source IP. `adapter` and
 * `lookupKey` describe, for the audit trace, WHERE the risk signal came from
 * (mock file vs. live MISP) and WHICH key was used.
 */
export interface RiskResolution {
  risk?: RiskContext;
  adapter: string;
  lookupKey: string;
  error?: string;
}

/**
 * A source of risk signals. `mock` reads a local JSON file; `misp` queries a
 * live MISP threat-intel instance by source IP.
 */
export interface RiskProvider {
  readonly mode: 'mock' | 'misp' | 'wazuh';
  resolveRisk(sourceIp: string | undefined): Promise<RiskResolution>;
}
