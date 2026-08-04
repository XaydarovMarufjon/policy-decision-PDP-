import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
} from '@nestjs/common';
import {
  AccessEvaluationInput,
  ContextBuildResult,
  ContextTraceEntry,
  DeviceContext,
  EvidenceEvaluationRequest,
  ResourceContext,
  RiskContext,
  SubjectContext,
} from '../pdp.types';
import {
  IDENTITY_PROVIDER,
  IdentityProvider,
  IdentityResolution,
} from './identity/identity-provider';
import {
  RISK_PROVIDER,
  RiskProvider,
  RiskResolution,
} from './risk/risk-provider';
import {
  DEVICE_PROVIDER,
  DeviceProvider,
  DeviceResolution,
} from './device/device-provider';
import {
  RESOURCE_PROVIDER,
  ResourceProvider,
  ResourceResolution,
} from './resource/resource-provider';

type JsonRecord = Record<string, unknown>;

@Injectable()
export class ContextBuilderService {
  // Canonical input is trusted verbatim (no token/signature check), so it is a
  // privilege-assertion path. Disabled by default; enable only for dev/test.
  private readonly allowCanonical =
    process.env.ALLOW_CANONICAL_INPUT === 'true';

  constructor(
    @Inject(IDENTITY_PROVIDER)
    private readonly identity: IdentityProvider,
    @Inject(RISK_PROVIDER)
    private readonly riskProvider: RiskProvider,
    @Inject(DEVICE_PROVIDER)
    private readonly deviceProvider: DeviceProvider,
    @Inject(RESOURCE_PROVIDER)
    private readonly resourceProvider: ResourceProvider,
  ) {}

  async build(request: unknown): Promise<ContextBuildResult> {
    const body = this.asRecord(request, 'request body');

    if (this.isCanonicalRequest(body)) {
      if (!this.allowCanonical) {
        throw new ForbiddenException(
          'Canonical input is disabled. Submit evidence input ' +
            '(subject_ref, device_evidence, resource_ref, action) so identity is verified.',
        );
      }
      return this.buildFromCanonical(body);
    }

    if (this.isEvidenceRequest(body)) {
      return this.buildFromEvidence(body);
    }

    throw new BadRequestException(
      'Request must be canonical input or evidence input with subject_ref, device_evidence, resource_ref, and action',
    );
  }

  private buildFromCanonical(body: JsonRecord): ContextBuildResult {
    const input = this.toCanonicalInput(body);

    return {
      requestId: this.optionalString(body.request_id),
      mode: 'canonical',
      input,
      sources: {
        identity: 'request.subject',
        device: 'request.device',
        risk: 'request.risk',
        resource: 'request.resource',
      },
      trace: [
        this.traceRequest('identity', 'request.subject', input.subject),
        this.traceRequest('device', 'request.device', input.device),
        this.traceRequest('risk', 'request.risk', input.risk),
        this.traceRequest('resource', 'request.resource', input.resource),
      ],
      warnings: [
        'Canonical request bypassed mock source enrichment. Use evidence format to exercise Context Builder adapters.',
      ],
    };
  }

  private async buildFromEvidence(
    body: JsonRecord,
  ): Promise<ContextBuildResult> {
    const request = body as unknown as EvidenceEvaluationRequest;
    const sourceIp = request.network?.source_ip;
    const trace: ContextTraceEntry[] = [];
    trace.push(
      this.traceRequest(
        'subject_ref',
        'request.subject_ref',
        request.subject_ref,
        true,
      ),
    );
    trace.push(
      this.traceRequest(
        'device_evidence',
        'request.device_evidence',
        request.device_evidence,
        true,
      ),
    );
    trace.push(
      this.traceRequest('network', 'request.network', request.network ?? {}, true),
    );
    trace.push(
      this.traceRequest(
        'resource_ref',
        'request.resource_ref',
        request.resource_ref,
        true,
      ),
    );

    if (request.risk_evidence) {
      trace.push(
        this.traceRequest(
          'risk_evidence',
          'request.risk_evidence',
          request.risk_evidence,
          true,
        ),
      );
    }

    // The four sources are independent. Resolve them concurrently so request
    // latency is bounded by the slowest provider instead of their sum.
    const [subjectLookup, deviceLookup, resourceLookup, riskLookup] =
      await Promise.all([
        this.resolveIdentity(request.subject_ref),
        this.resolveDeviceSource(request.device_evidence),
        this.resolveResourceSource(request.resource_ref),
        this.resolveRiskSource(sourceIp),
      ]);
    trace.push(
      subjectLookup.trace,
      deviceLookup.trace,
      resourceLookup.trace,
      riskLookup.trace,
    );

    const subject = subjectLookup.result;
    const device = deviceLookup.result;
    const resource = resourceLookup.result;
    const sourceRisk = riskLookup.result;

    if (!subject) {
      throw new BadRequestException(
        subjectLookup.trace.error ?? 'Unable to resolve subject_ref',
      );
    }

    if (!device) {
      throw new BadRequestException(
        deviceLookup.trace.error ?? 'Unable to resolve device_evidence',
      );
    }

    if (!resource) {
      throw new BadRequestException(
        resourceLookup.trace.error ?? 'Unable to resolve resource_ref',
      );
    }

    if (!sourceRisk) {
      throw new BadRequestException('Unable to resolve risk context');
    }

    const risk = this.mergeRisk(sourceRisk, request.risk_evidence);

    return {
      requestId: this.optionalString(body.request_id),
      mode: 'evidence',
      input: {
        subject,
        device: {
          ...device,
          ip: sourceIp ?? device.ip,
        },
        risk,
        resource,
        action: request.action,
      },
      sources: {
        identity: `${subjectLookup.adapter}:${subjectLookup.trace.lookupKey}`,
        device: `${deviceLookup.adapter}:${deviceLookup.trace.lookupKey}`,
        risk: `${riskLookup.adapter}:${riskLookup.trace.lookupKey}`,
        resource: `${resourceLookup.adapter}:${resourceLookup.trace.lookupKey}`,
      },
      trace,
      warnings: [],
    };
  }

  private traceRequest(
    operation: string,
    lookupKey: string,
    result: unknown,
    redacted = false,
  ): ContextTraceEntry {
    return {
      source: 'request',
      adapter: 'manual-json',
      operation,
      lookupKey,
      status: 'ok',
      durationMs: 0,
      redacted,
      result: redacted ? this.sanitizeTracePayload(result) : result,
    };
  }

  private async resolveIdentity(
    ref: EvidenceEvaluationRequest['subject_ref'],
  ): Promise<{
    result?: SubjectContext;
    adapter: string;
    trace: ContextTraceEntry;
  }> {
    const started = process.hrtime.bigint();

    try {
      const resolution: IdentityResolution =
        await this.identity.resolveSubject(ref);
      const durationMs = this.elapsedMs(started);
      const status: ContextTraceEntry['status'] = resolution.subject
        ? 'ok'
        : resolution.error
          ? 'error'
          : 'miss';

      return {
        result: resolution.subject,
        adapter: resolution.adapter,
        trace: {
          source: 'identity',
          adapter: resolution.adapter,
          operation: 'resolve_subject',
          lookupKey: resolution.lookupKey,
          status,
          durationMs,
          redacted: true,
          result: resolution.subject
            ? this.sanitizeTraceResult('identity', resolution.subject)
            : undefined,
          error: resolution.error,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        result: undefined,
        adapter: this.identity.mode === 'oidc' ? 'oidc' : 'identity',
        trace: {
          source: 'identity',
          adapter: this.identity.mode === 'oidc' ? 'oidc' : 'identity',
          operation: 'resolve_subject',
          lookupKey: `${ref.type}:<error>`,
          status: 'error',
          durationMs: this.elapsedMs(started),
          redacted: true,
          error: message,
        },
      };
    }
  }

  private async resolveRiskSource(sourceIp: string | undefined): Promise<{
    result?: RiskContext;
    adapter: string;
    trace: ContextTraceEntry;
  }> {
    const started = process.hrtime.bigint();

    try {
      const resolution: RiskResolution =
        await this.riskProvider.resolveRisk(sourceIp);
      const durationMs = this.elapsedMs(started);
      const status: ContextTraceEntry['status'] = resolution.error
        ? 'error'
        : resolution.risk
          ? 'ok'
          : 'miss';

      return {
        result: resolution.risk,
        adapter: resolution.adapter,
        trace: {
          source: 'risk',
          adapter: resolution.adapter,
          operation: 'resolve_risk',
          lookupKey: resolution.lookupKey,
          status,
          durationMs,
          redacted: true,
          result: resolution.risk
            ? this.sanitizeTraceResult('risk', resolution.risk)
            : undefined,
          error: resolution.error,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        result: undefined,
        adapter: this.riskProvider.mode === 'misp' ? 'misp' : 'risk',
        trace: {
          source: 'risk',
          adapter: this.riskProvider.mode === 'misp' ? 'misp' : 'risk',
          operation: 'resolve_risk',
          lookupKey: sourceIp ?? 'default',
          status: 'error',
          durationMs: this.elapsedMs(started),
          redacted: true,
          error: message,
        },
      };
    }
  }

  private async resolveDeviceSource(
    evidence: EvidenceEvaluationRequest['device_evidence'],
  ): Promise<{
    result?: DeviceContext;
    adapter: string;
    trace: ContextTraceEntry;
  }> {
    const started = process.hrtime.bigint();

    try {
      const resolution: DeviceResolution =
        await this.deviceProvider.resolveDevice(evidence);
      const durationMs = this.elapsedMs(started);
      const status: ContextTraceEntry['status'] = resolution.error
        ? 'error'
        : resolution.device
          ? 'ok'
          : 'miss';

      return {
        result: resolution.device,
        adapter: resolution.adapter,
        trace: {
          source: 'device',
          adapter: resolution.adapter,
          operation: 'resolve_device',
          lookupKey: resolution.lookupKey,
          status,
          durationMs,
          redacted: true,
          result: resolution.device
            ? this.sanitizeTraceResult('device', resolution.device)
            : undefined,
          error: resolution.error,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        result: undefined,
        adapter: this.deviceProvider.mode === 'wazuh' ? 'wazuh' : 'device',
        trace: {
          source: 'device',
          adapter: this.deviceProvider.mode === 'wazuh' ? 'wazuh' : 'device',
          operation: 'resolve_device',
          lookupKey: evidence?.device_id ?? '<missing>',
          status: 'error',
          durationMs: this.elapsedMs(started),
          redacted: true,
          error: message,
        },
      };
    }
  }

  private async resolveResourceSource(
    ref: EvidenceEvaluationRequest['resource_ref'],
  ): Promise<{
    result?: ResourceContext;
    adapter: string;
    trace: ContextTraceEntry;
  }> {
    const started = process.hrtime.bigint();

    try {
      const resolution: ResourceResolution =
        await this.resourceProvider.resolveResource(ref);
      const durationMs = this.elapsedMs(started);
      const status: ContextTraceEntry['status'] = resolution.error
        ? 'error'
        : resolution.resource
          ? 'ok'
          : 'miss';

      return {
        result: resolution.resource,
        adapter: resolution.adapter,
        trace: {
          source: 'resource',
          adapter: resolution.adapter,
          operation: 'resolve_resource',
          lookupKey: resolution.lookupKey,
          status,
          durationMs,
          redacted: true,
          result: resolution.resource
            ? this.sanitizeTraceResult('resource', resolution.resource)
            : undefined,
          error: resolution.error,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        result: undefined,
        adapter:
          this.resourceProvider.mode === 'opa-data' ? 'opa-data' : 'resource',
        trace: {
          source: 'resource',
          adapter:
            this.resourceProvider.mode === 'opa-data' ? 'opa-data' : 'resource',
          operation: 'resolve_resource',
          lookupKey: ref.resource_id,
          status: 'error',
          durationMs: this.elapsedMs(started),
          redacted: true,
          error: message,
        },
      };
    }
  }

  private sanitizeTraceResult(source: string, result: unknown): unknown {
    if (!this.isRecord(result)) {
      return result;
    }

    if (source === 'identity') {
      return {
        user: result.user,
        role: result.role,
        department: result.department,
        mfa: result.mfa,
      };
    }

    if (source === 'device') {
      return {
        managed: result.managed,
        edr_status: result.edr_status,
        patch_level: result.patch_level,
        ip: result.ip,
      };
    }

    return result;
  }

  private sanitizeTracePayload(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((item) => this.sanitizeTracePayload(item));
    }

    if (!this.isRecord(value)) {
      return value;
    }

    const sanitized: JsonRecord = {};

    for (const [key, rawValue] of Object.entries(value)) {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes('token') ||
        lowerKey.includes('fingerprint') ||
        lowerKey.includes('session')
      ) {
        sanitized[key] =
          typeof rawValue === 'string' ? this.mask(rawValue) : '<redacted>';
      } else {
        sanitized[key] = this.sanitizeTracePayload(rawValue);
      }
    }

    return sanitized;
  }

  private mask(value: string | undefined): string {
    if (!value) {
      return '<missing>';
    }

    if (value.length <= 8) {
      return '***';
    }

    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }

  private elapsedMs(started: bigint): number {
    const elapsedNs = process.hrtime.bigint() - started;
    return Number(elapsedNs / 1_000_000n);
  }

  private toCanonicalInput(body: JsonRecord): AccessEvaluationInput {
    const subject = this.asRecord(body.subject, 'subject');
    const device = this.asRecord(body.device, 'device');
    const risk = this.asRecord(body.risk, 'risk');
    const resource = this.asRecord(body.resource, 'resource');

    return {
      subject: {
        user: this.requiredString(subject.user, 'subject.user'),
        role: this.requiredString(subject.role, 'subject.role'),
        department: this.requiredString(
          subject.department,
          'subject.department',
        ),
        mfa: this.requiredBoolean(subject.mfa, 'subject.mfa'),
      },
      device: {
        managed: this.requiredBoolean(device.managed, 'device.managed'),
        edr_status: this.requiredString(
          device.edr_status,
          'device.edr_status',
        ),
        patch_level: this.requiredString(
          device.patch_level,
          'device.patch_level',
        ),
        ip: this.requiredString(device.ip, 'device.ip'),
      },
      risk: {
        siem_score: this.requiredNumber(risk.siem_score, 'risk.siem_score'),
        threat_intel_match: this.requiredBoolean(
          risk.threat_intel_match,
          'risk.threat_intel_match',
        ),
        impossible_travel: this.requiredBoolean(
          risk.impossible_travel,
          'risk.impossible_travel',
        ),
      },
      resource: {
        type: this.requiredString(resource.type, 'resource.type'),
        name: this.requiredString(resource.name, 'resource.name'),
        criticality: this.requiredString(
          resource.criticality,
          'resource.criticality',
        ),
      },
      action: this.requiredString(body.action, 'action'),
    };
  }

  private mergeRisk(
    sourceRisk: RiskContext,
    override: Partial<RiskContext> | undefined,
  ): RiskContext {
    if (!override) {
      return sourceRisk;
    }

    return {
      siem_score:
        typeof override.siem_score === 'number'
          ? override.siem_score
          : sourceRisk.siem_score,
      threat_intel_match:
        typeof override.threat_intel_match === 'boolean'
          ? override.threat_intel_match
          : sourceRisk.threat_intel_match,
      impossible_travel:
        typeof override.impossible_travel === 'boolean'
          ? override.impossible_travel
          : sourceRisk.impossible_travel,
    };
  }

  private isCanonicalRequest(body: JsonRecord): boolean {
    return (
      this.isRecord(body.subject) &&
      this.isRecord(body.device) &&
      this.isRecord(body.risk) &&
      this.isRecord(body.resource) &&
      typeof body.action === 'string'
    );
  }

  private isEvidenceRequest(body: JsonRecord): boolean {
    return (
      this.isRecord(body.subject_ref) &&
      this.isRecord(body.device_evidence) &&
      this.isRecord(body.resource_ref) &&
      typeof body.action === 'string'
    );
  }

  private asRecord(value: unknown, field: string): JsonRecord {
    if (!this.isRecord(value)) {
      throw new BadRequestException(`${field} must be an object`);
    }

    return value;
  }

  private isRecord(value: unknown): value is JsonRecord {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  private requiredString(value: unknown, field: string): string {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new BadRequestException(`${field} must be a non-empty string`);
    }

    return value;
  }

  private optionalString(value: unknown): string | undefined {
    return typeof value === 'string' && value.trim() !== '' ? value : undefined;
  }

  private requiredBoolean(value: unknown, field: string): boolean {
    if (typeof value !== 'boolean') {
      throw new BadRequestException(`${field} must be a boolean`);
    }

    return value;
  }

  private requiredNumber(value: unknown, field: string): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new BadRequestException(`${field} must be a finite number`);
    }

    return value;
  }
}
