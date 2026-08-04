import { Logger, Provider } from '@nestjs/common';
import { MockSourceRepository } from '../mock-source.repository';
import { DEVICE_PROVIDER, DeviceProvider } from './device-provider';
import { MockDeviceProvider } from './mock-device.provider';
import { WazuhDeviceProvider } from './wazuh-device.provider';

/**
 * Selects the device posture provider from DEVICE_MODE:
 *   mock (default) -> local mock-sources/devices.json
 *   wazuh          -> live Wazuh EDR posture lookup by hostname
 */
export const deviceProviderFactory: Provider = {
  provide: DEVICE_PROVIDER,
  inject: [MockSourceRepository],
  useFactory: (sources: MockSourceRepository): DeviceProvider => {
    const mode = (process.env.DEVICE_MODE ?? 'mock').toLowerCase();
    const logger = new Logger('DeviceProviderFactory');

    if (mode === 'wazuh') {
      logger.log('DEVICE_MODE=wazuh -> using live Wazuh device posture provider');
      return new WazuhDeviceProvider();
    }

    if (mode !== 'mock') {
      throw new Error(
        `Unsupported DEVICE_MODE="${mode}" (expected mock or wazuh)`,
      );
    }

    return new MockDeviceProvider(sources);
  },
};
