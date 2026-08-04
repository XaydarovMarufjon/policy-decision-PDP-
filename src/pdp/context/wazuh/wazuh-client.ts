import { Logger } from '@nestjs/common';
import { httpJson } from './http-json';

/**
 * Shared client for the two Wazuh backends:
 *   - Server API (default :55000) — Basic-auth to obtain a JWT (default 900s
 *     TTL), then Bearer for agent/posture queries. Token is cached and
 *     re-fetched before expiry / on 401.
 *   - Indexer / OpenSearch (default :9200) — Basic auth for alert & vulnerability
 *     queries (wazuh-alerts-*, wazuh-states-vulnerabilities-*).
 *
 * Both are HTTPS with a self-signed cert by default → WAZUH_VERIFY_TLS toggles
 * certificate verification.
 *
 * Configuration (env):
 *   WAZUH_API_URL / WAZUH_API_USER / WAZUH_API_PASSWORD          (server API)
 *   WAZUH_INDEXER_URL / WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD (indexer)
 *   WAZUH_VERIFY_TLS   "false" to accept self-signed (default true)
 *   WAZUH_TIMEOUT_MS   per-request timeout (default 4000)
 *   WAZUH_ALERTS_INDEX default "wazuh-alerts-*"
 *   WAZUH_VULN_INDEX   default "wazuh-states-vulnerabilities-*"
 *   WAZUH_ALERTS_WINDOW default "24h"
 */
export interface WazuhAgent {
  id: string;
  name?: string;
  ip?: string;
  status?: string;
  lastKeepAlive?: string;
}

export class WazuhClient {
  private readonly logger = new Logger(WazuhClient.name);

  readonly apiUrl = (process.env.WAZUH_API_URL ?? '').replace(/\/$/, '');
  private readonly apiUser = process.env.WAZUH_API_USER ?? '';
  private readonly apiPassword = process.env.WAZUH_API_PASSWORD ?? '';

  readonly indexerUrl = (process.env.WAZUH_INDEXER_URL ?? '').replace(/\/$/, '');
  private readonly indexerUser = process.env.WAZUH_INDEXER_USER ?? '';
  private readonly indexerPassword = process.env.WAZUH_INDEXER_PASSWORD ?? '';

  private readonly verifyTls = process.env.WAZUH_VERIFY_TLS !== 'false';
  private readonly timeoutMs = Number(process.env.WAZUH_TIMEOUT_MS ?? 4000);
  private readonly alertsIndex =
    process.env.WAZUH_ALERTS_INDEX ?? 'wazuh-alerts-*';
  private readonly vulnIndex =
    process.env.WAZUH_VULN_INDEX ?? 'wazuh-states-vulnerabilities-*';
  private readonly alertsWindow = process.env.WAZUH_ALERTS_WINDOW ?? '24h';

  // Cached server-API JWT. Re-fetched before the 900s TTL expires.
  private token?: string;
  private tokenExpiresAt = 0;
  private static readonly TOKEN_TTL_MS = 10 * 60 * 1000; // refresh at 10m (< 15m)

  constructor() {
    const missing: string[] = [];
    if (!this.apiUrl) missing.push('WAZUH_API_URL');
    if (!this.apiUser) missing.push('WAZUH_API_USER');
    if (!this.apiPassword) missing.push('WAZUH_API_PASSWORD');
    if (!this.indexerUrl) missing.push('WAZUH_INDEXER_URL');
    if (!this.indexerUser) missing.push('WAZUH_INDEXER_USER');
    if (!this.indexerPassword) missing.push('WAZUH_INDEXER_PASSWORD');
    if (missing.length > 0) {
      throw new Error(
        `Wazuh integration requires ${missing.join(', ')} to be set.`,
      );
    }
    this.logger.log(
      `Wazuh client active (api=${this.apiUrl}, indexer=${this.indexerUrl}, verifyTls=${this.verifyTls})`,
    );
  }

  private basic(user: string, password: string): string {
    return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
  }

  /** Obtain (and cache) a server-API JWT. */
  private async apiToken(now: number): Promise<string> {
    if (this.token && now < this.tokenExpiresAt) {
      return this.token;
    }
    const res = await httpJson(`${this.apiUrl}/security/user/authenticate`, {
      method: 'POST',
      headers: { Authorization: this.basic(this.apiUser, this.apiPassword) },
      timeoutMs: this.timeoutMs,
      rejectUnauthorized: this.verifyTls,
    });
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Wazuh authenticate failed (HTTP ${res.status})`);
    }
    const token = (res.json as { data?: { token?: string } })?.data?.token;
    if (!token) {
      throw new Error('Wazuh authenticate returned no token');
    }
    this.token = token;
    this.tokenExpiresAt = now + WazuhClient.TOKEN_TTL_MS;
    return token;
  }

  /** Look up an agent by hostname (preferred) or IP. */
  async getAgent(
    now: number,
    opts: { name?: string; ip?: string },
  ): Promise<WazuhAgent | undefined> {
    const token = await this.apiToken(now);
    const params = new URLSearchParams({
      select: 'id,name,ip,status,lastKeepAlive',
      limit: '1',
    });
    if (opts.name) {
      params.set('name', opts.name);
    } else if (opts.ip) {
      params.set('ip', opts.ip);
    } else {
      return undefined;
    }

    const res = await httpJson(`${this.apiUrl}/agents?${params.toString()}`, {
      headers: { Authorization: `Bearer ${token}` },
      timeoutMs: this.timeoutMs,
      rejectUnauthorized: this.verifyTls,
    });
    if (res.status === 401) {
      // Token expired mid-flight: drop cache so the next call re-auths.
      this.token = undefined;
      throw new Error('Wazuh API returned 401 (token expired)');
    }
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Wazuh /agents failed (HTTP ${res.status})`);
    }
    const items =
      (res.json as { data?: { affected_items?: WazuhAgent[] } })?.data
        ?.affected_items ?? [];
    return items[0];
  }

  /** Count Critical/High open vulnerabilities for an agent (indexer). */
  async countHighVulnerabilities(agentId: string): Promise<number> {
    const body = JSON.stringify({
      size: 0,
      track_total_hits: true,
      query: {
        bool: {
          filter: [
            { term: { 'agent.id': agentId } },
            { terms: { 'vulnerability.severity': ['Critical', 'High'] } },
          ],
        },
      },
    });
    const res = await httpJson(`${this.indexerUrl}/${this.vulnIndex}/_search`, {
      method: 'POST',
      headers: {
        Authorization: this.basic(this.indexerUser, this.indexerPassword),
        'Content-Type': 'application/json',
      },
      body,
      timeoutMs: this.timeoutMs,
      rejectUnauthorized: this.verifyTls,
    });
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Wazuh vuln search failed (HTTP ${res.status})`);
    }
    const total = (res.json as { hits?: { total?: { value?: number } } })?.hits
      ?.total?.value;
    return typeof total === 'number' ? total : 0;
  }

  /** Highest alert rule.level for a host/IP in the recent window (indexer). */
  async maxAlertLevel(opts: {
    host?: string;
    ip?: string;
  }): Promise<number> {
    const should: unknown[] = [];
    if (opts.host) should.push({ term: { 'agent.name': opts.host } });
    if (opts.ip) should.push({ term: { 'data.srcip': opts.ip } });
    if (should.length === 0) {
      return 0;
    }

    const body = JSON.stringify({
      size: 0,
      query: {
        bool: {
          filter: [
            { range: { '@timestamp': { gte: `now-${this.alertsWindow}` } } },
          ],
          should,
          minimum_should_match: 1,
        },
      },
      aggs: { max_level: { max: { field: 'rule.level' } } },
    });
    const res = await httpJson(
      `${this.indexerUrl}/${this.alertsIndex}/_search`,
      {
        method: 'POST',
        headers: {
          Authorization: this.basic(this.indexerUser, this.indexerPassword),
          'Content-Type': 'application/json',
        },
        body,
        timeoutMs: this.timeoutMs,
        rejectUnauthorized: this.verifyTls,
      },
    );
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Wazuh alerts search failed (HTTP ${res.status})`);
    }
    const value = (
      res.json as { aggregations?: { max_level?: { value?: number | null } } }
    )?.aggregations?.max_level?.value;
    return typeof value === 'number' ? value : 0;
  }
}
