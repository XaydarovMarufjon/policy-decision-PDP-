import { Injectable, Logger } from '@nestjs/common';
import { RiskContext } from '../../pdp.types';
import { RiskProvider, RiskResolution } from './risk-provider';
import { httpJson } from '../wazuh/http-json';

/**
 * Real risk provider. Queries a live MISP threat-intel instance for the request
 * source IP and derives the risk context from any matching indicators.
 *
 * Enabled with RISK_MODE=misp. Configuration (env):
 *   MISP_URL         base URL, e.g. http://misp-core:80
 *   MISP_API_KEY     MISP automation (auth) key
 *   MISP_TIMEOUT_MS  per-request timeout (default 4000)
 *   MISP_FAIL_OPEN   "true" to treat MISP errors as benign; default is
 *                    fail-closed (a high risk score so OPA denies).
 *
 * Mapping: any ip-src/ip-dst attribute hit -> threat_intel_match=true and a
 * siem_score derived from the highest event threat level. No hit -> benign.
 * impossible_travel is not provided by MISP (left false; may be overridden by
 * the request's risk_evidence in the Context Builder merge).
 */
@Injectable()
export class MispRiskProvider implements RiskProvider {
  readonly mode = 'misp' as const;

  private readonly logger = new Logger(MispRiskProvider.name);
  private readonly baseUrl = (process.env.MISP_URL ?? '').replace(/\/$/, '');
  private readonly apiKey = process.env.MISP_API_KEY ?? '';
  private readonly timeoutMs = Number(process.env.MISP_TIMEOUT_MS ?? 4000);
  private readonly verifyTls = process.env.MISP_VERIFY_TLS !== 'false';
  private readonly failOpen = process.env.MISP_FAIL_OPEN === 'true';

  // threat_level_id (1=High..4=Undefined) -> siem_score
  private readonly threatLevelScore: Record<string, number> = {
    '1': 90,
    '2': 60,
    '3': 30,
    '4': 15,
  };

  constructor() {
    if (!this.baseUrl || !this.apiKey) {
      throw new Error(
        'RISK_MODE=misp requires MISP_URL and MISP_API_KEY to be set.',
      );
    }
    this.logger.log(`MISP risk provider active (url=${this.baseUrl})`);
  }

  async resolveRisk(sourceIp: string | undefined): Promise<RiskResolution> {
    const adapter = `misp:${this.baseUrl}`;
    const benign: RiskContext = {
      siem_score: 0,
      threat_intel_match: false,
      impossible_travel: false,
    };

    if (!sourceIp) {
      return { risk: benign, adapter, lookupKey: 'no-source-ip' };
    }

    try {
      const attributes = await this.search(sourceIp);

      if (attributes.length === 0) {
        return { risk: benign, adapter, lookupKey: sourceIp };
      }

      const siemScore = this.scoreFromAttributes(attributes);
      return {
        risk: {
          siem_score: siemScore,
          threat_intel_match: true,
          impossible_travel: false,
        },
        adapter,
        lookupKey: sourceIp,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // Fail-closed by default: if MISP can't be reached, treat as high risk so
      // OPA denies, rather than silently allowing an unchecked request.
      const risk: RiskContext = this.failOpen
        ? benign
        : { siem_score: 100, threat_intel_match: false, impossible_travel: false };

      return {
        risk,
        adapter,
        lookupKey: sourceIp,
        error: `MISP lookup failed (${this.failOpen ? 'fail-open' : 'fail-closed'}): ${message}`,
      };
    }
  }

  private async search(value: string): Promise<MispAttribute[]> {
    const res = await httpJson(`${this.baseUrl}/attributes/restSearch`, {
        method: 'POST',
        headers: {
          Authorization: this.apiKey,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          returnFormat: 'json',
          value,
          type: ['ip-src', 'ip-dst'],
          includeEventTags: true,
          limit: 50,
        }),
        timeoutMs: this.timeoutMs,
        rejectUnauthorized: this.verifyTls,
    });

    if (res.status < 200 || res.status >= 300) {
      throw new Error(`HTTP ${res.status}`);
    }

    const body = res.json as {
      response?: { Attribute?: MispAttribute[] };
    };
    return body.response?.Attribute ?? [];
  }

  private scoreFromAttributes(attributes: MispAttribute[]): number {
    let best = 15;
    for (const attr of attributes) {
      const level = attr.Event?.threat_level_id;
      const score = level ? this.threatLevelScore[level] : undefined;
      if (score && score > best) {
        best = score;
      }
    }
    return best;
  }
}

interface MispAttribute {
  value?: string;
  type?: string;
  Event?: { id?: string; info?: string; threat_level_id?: string };
}
