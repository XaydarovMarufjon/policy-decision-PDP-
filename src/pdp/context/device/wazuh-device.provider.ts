import { Injectable, Logger } from '@nestjs/common';
import { DeviceContext, DeviceEvidence } from '../../pdp.types';
import { WazuhClient } from '../wazuh/wazuh-client';
import { DeviceProvider, DeviceResolution } from './device-provider';

/**
 * Real device posture provider. Looks the request's device up in Wazuh (by
 * hostname) and derives the canonical posture from the agent record:
 *   managed     = agent exists AND status === 'active'
 *   edr_status  = 'healthy' when active & keepalive fresh, else 'unhealthy'
 *   patch_level = 'ok' when 0 Critical/High vulnerabilities, else 'outdated'
 *
 * Enabled with DEVICE_MODE=wazuh. Fail-closed by default: any Wazuh error (or a
 * missing agent) yields a deny-forcing posture (managed:false) so OPA denies,
 * rather than silently trusting an unverifiable device. WAZUH_FAIL_OPEN=true
 * flips that to a benign posture (NOT recommended).
 */
@Injectable()
export class WazuhDeviceProvider implements DeviceProvider {
  readonly mode = 'wazuh' as const;

  private readonly logger = new Logger(WazuhDeviceProvider.name);
  private readonly client = new WazuhClient();
  private readonly failOpen = process.env.WAZUH_FAIL_OPEN === 'true';
  private readonly staleMs = Number(process.env.WAZUH_STALE_MS ?? 900000); // 15m

  async resolveDevice(evidence: DeviceEvidence): Promise<DeviceResolution> {
    const adapter = `wazuh:${this.client.apiUrl}`;
    const host = evidence?.hostname;
    const lookupKey = host ?? evidence?.device_id ?? '<missing>';

    try {
      const agent = await this.client.getAgent(Date.now(), { name: host });

      if (!agent) {
        // Unknown to Wazuh => unmanaged (deny-forcing), not an error.
        return {
          device: {
            managed: false,
            edr_status: 'unknown',
            patch_level: 'unknown',
            ip: '',
          },
          adapter,
          lookupKey,
          error: `No Wazuh agent found for "${lookupKey}"`,
        };
      }

      const active = agent.status === 'active';
      const fresh = this.isFresh(agent.lastKeepAlive);
      const managed = active;
      const edr_status = active && fresh ? 'healthy' : 'unhealthy';

      let patch_level = 'unknown';
      if (managed) {
        const highVulns = await this.client.countHighVulnerabilities(agent.id);
        patch_level = highVulns === 0 ? 'ok' : 'outdated';
      }

      const device: DeviceContext = {
        managed,
        edr_status,
        patch_level,
        ip: agent.ip ?? '',
      };

      return { device, adapter, lookupKey };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Wazuh device lookup failed for ${lookupKey}: ${message}`);

      const device: DeviceContext = this.failOpen
        ? { managed: true, edr_status: 'healthy', patch_level: 'ok', ip: '' }
        : {
            managed: false,
            edr_status: 'unreachable',
            patch_level: 'unknown',
            ip: '',
          };

      return {
        device,
        adapter,
        lookupKey,
        error: `Wazuh device lookup failed (${this.failOpen ? 'fail-open' : 'fail-closed'}): ${message}`,
      };
    }
  }

  private isFresh(lastKeepAlive: string | undefined): boolean {
    if (!lastKeepAlive) {
      return false;
    }
    const ts = Date.parse(lastKeepAlive);
    if (Number.isNaN(ts)) {
      return false;
    }
    return Date.now() - ts <= this.staleMs;
  }
}
