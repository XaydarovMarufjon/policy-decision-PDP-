import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  DeviceContext,
  ResourceContext,
  RiskContext,
  SubjectContext,
  SubjectRef,
} from '../pdp.types';

interface IdentitySource {
  tokens: Record<string, string>;
  users: Record<string, SubjectContext>;
}

interface DeviceSource {
  devices: Record<string, DeviceContext>;
}

interface RiskSource {
  default: RiskContext;
  by_source_ip: Record<string, RiskContext>;
}

interface ResourceSource {
  resources: Record<string, ResourceContext>;
}

@Injectable()
export class MockSourceRepository {
  private readonly sourceDir =
    process.env.CONTEXT_SOURCE_DIR ?? join(process.cwd(), 'mock-sources');

  private readonly identity = this.readJson<IdentitySource>('identity.json');
  private readonly devices = this.readJson<DeviceSource>('devices.json');
  private readonly risks = this.readJson<RiskSource>('risks.json');
  private readonly resources = this.readJson<ResourceSource>('resources.json');

  resolveSubject(ref: SubjectRef): SubjectContext | undefined {
    if (ref.type === 'user_id') {
      return ref.user_id ? this.identity.users[ref.user_id] : undefined;
    }

    if (ref.type === 'jwt' || ref.type === 'mock_token') {
      if (!ref.token) {
        return undefined;
      }

      const userId = this.identity.tokens[ref.token];
      return userId ? this.identity.users[userId] : undefined;
    }

    return undefined;
  }

  resolveDevice(deviceId: string | undefined): DeviceContext | undefined {
    return deviceId ? this.devices.devices[deviceId] : undefined;
  }

  resolveRisk(sourceIp: string | undefined): RiskContext {
    if (!sourceIp) {
      return this.risks.default;
    }

    return this.risks.by_source_ip[sourceIp] ?? this.risks.default;
  }

  resolveResource(resourceId: string): ResourceContext | undefined {
    return this.resources.resources[resourceId];
  }

  private readJson<T>(fileName: string): T {
    try {
      const filePath = join(this.sourceDir, fileName);
      return JSON.parse(readFileSync(filePath, 'utf8')) as T;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new InternalServerErrorException(
        `Failed to load context source ${fileName}: ${message}`,
      );
    }
  }
}
