import { DeviceContext, DeviceEvidence } from '../../pdp.types';

/**
 * Injection token for the active DeviceProvider implementation, selected at
 * module wiring time from the DEVICE_MODE environment variable.
 */
export const DEVICE_PROVIDER = 'DEVICE_PROVIDER';

/**
 * Result of resolving device posture from the request's device evidence.
 * `adapter` and `lookupKey` describe, for the audit trace, WHERE the posture
 * came from (mock file vs. live EDR) and WHICH key was used.
 */
export interface DeviceResolution {
  device?: DeviceContext;
  adapter: string;
  lookupKey: string;
  error?: string;
}

/**
 * A source of device posture. `mock` reads a local JSON file; `wazuh` (P2)
 * queries a live Wazuh instance for per-agent posture (managed / EDR / patch).
 */
export interface DeviceProvider {
  readonly mode: 'mock' | 'wazuh';
  resolveDevice(evidence: DeviceEvidence): Promise<DeviceResolution>;
}
