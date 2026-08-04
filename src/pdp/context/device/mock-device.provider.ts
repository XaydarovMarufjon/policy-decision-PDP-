import { Injectable } from '@nestjs/common';
import { DeviceEvidence } from '../../pdp.types';
import { MockSourceRepository } from '../mock-source.repository';
import { DeviceProvider, DeviceResolution } from './device-provider';

/**
 * Default device provider. Resolves device posture from the local
 * mock-sources/devices.json file, keyed by device_id. Used when DEVICE_MODE=mock
 * (default), so the stack keeps running without a real EDR.
 */
@Injectable()
export class MockDeviceProvider implements DeviceProvider {
  readonly mode = 'mock' as const;

  constructor(private readonly sources: MockSourceRepository) {}

  async resolveDevice(evidence: DeviceEvidence): Promise<DeviceResolution> {
    const deviceId = evidence?.device_id;

    return {
      device: this.sources.resolveDevice(deviceId),
      adapter: 'mock-sources/devices.json',
      lookupKey: deviceId ?? '<missing>',
    };
  }
}
