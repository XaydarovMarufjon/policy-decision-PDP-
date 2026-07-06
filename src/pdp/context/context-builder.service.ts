import { BadRequestException, Injectable } from '@nestjs/common';
import {
  AccessEvaluationInput,
  ContextBuildResult,
  ContextTraceEntry,
  EvidenceEvaluationRequest,
  RiskContext,
} from '../pdp.types';
import { MockSourceRepository } from './mock-source.repository';

type JsonRecord = Record<string, unknown>;

@Injectable()
export class ContextBuilderService {
  constructor(private readonly sources: MockSourceRepository) {}

  build(request: unknown): ContextBuildResult {
    const body = this.asRecord(request, 'request body');

    if (this.isCanonicalRequest(body)) {
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

  private buildFromEvidence(body: JsonRecord): ContextBuildResult {
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

    const subjectLookup = this.traceLookup(
      'identity',
      'mock-sources/identity.json',
      'resolve_subject',
      this.subjectLookupKey(request.subject_ref),
      () => this.sources.resolveSubject(request.subject_ref),
    );
    trace.push(subjectLookup.trace);

    const deviceId = request.device_evidence?.device_id;
    const deviceLookup = this.traceLookup(
      'device',
      'mock-sources/devices.json',
      'resolve_device',
      deviceId ?? '<missing>',
      () => this.sources.resolveDevice(deviceId),
    );
    trace.push(deviceLookup.trace);

    const resourceLookup = this.traceLookup(
      'resource',
      'mock-sources/resources.json',
      'resolve_resource',
      request.resource_ref.resource_id,
      () => this.sources.resolveResource(request.resource_ref.resource_id),
    );
    trace.push(resourceLookup.trace);

    const riskLookup = this.traceLookup(
      'risk',
      'mock-sources/risks.json',
      'resolve_risk',
      sourceIp ?? 'default',
      () => this.sources.resolveRisk(sourceIp),
    );
    trace.push(riskLookup.trace);

    const subject = subjectLookup.result;
    const device = deviceLookup.result;
    const resource = resourceLookup.result;
    const sourceRisk = riskLookup.result;

    if (!subject) {
      throw new BadRequestException('Unable to resolve subject_ref');
    }

    if (!device) {
      throw new BadRequestException('Unable to resolve device_evidence');
    }

    if (!resource) {
      throw new BadRequestException('Unable to resolve resource_ref');
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
        identity: `mock-sources/identity.json:${request.subject_ref.type}`,
        device: `mock-sources/devices.json:${request.device_evidence.device_id}`,
        risk: sourceIp
          ? `mock-sources/risks.json:${sourceIp}`
          : 'mock-sources/risks.json:default',
        resource: `mock-sources/resources.json:${request.resource_ref.resource_id}`,
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

  private traceLookup<T>(
    source: 'identity' | 'device' | 'risk' | 'resource',
    adapter: string,
    operation: string,
    lookupKey: string,
    lookup: () => T | undefined,
  ): { result: T | undefined; trace: ContextTraceEntry } {
    const started = process.hrtime.bigint();

    try {
      const result = lookup();
      const durationMs = this.elapsedMs(started);

      return {
        result,
        trace: {
          source,
          adapter,
          operation,
          lookupKey,
          status: result ? 'ok' : 'miss',
          durationMs,
          redacted: true,
          result: result ? this.sanitizeTraceResult(source, result) : undefined,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      return {
        result: undefined,
        trace: {
          source,
          adapter,
          operation,
          lookupKey,
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

  private subjectLookupKey(
    ref: EvidenceEvaluationRequest['subject_ref'],
  ): string {
    if (ref.type === 'jwt' || ref.type === 'mock_token') {
      return `${ref.type}:${this.mask(ref.token)}`;
    }

    return `${ref.type}:${ref.user_id ?? '<missing>'}`;
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
