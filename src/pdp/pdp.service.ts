import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { ContextBuilderService } from './context/context-builder.service';
import { OpaPolicyEngineService } from './policy-engine/opa-policy-engine.service';
import { PolicyAdministratorService } from './policy-administrator/policy-administrator.service';
import { AuditLogService } from './audit/audit-log.service';
import {
  AccessEvaluationInput,
  AdministratorDecision,
  EngineDecision,
  PdpResponse,
  PdpRouteStep,
} from './pdp.types';

@Injectable()
export class PdpService {
  constructor(
    private readonly contextBuilder: ContextBuilderService,
    private readonly policyEngine: OpaPolicyEngineService,
    private readonly policyAdministrator: PolicyAdministratorService,
    private readonly auditLog: AuditLogService,
  ) {}

  get opaDecisionUrl(): string {
    return this.policyEngine.opaDecisionUrl;
  }

  async evaluate(request: unknown): Promise<PdpResponse> {
    const context = this.contextBuilder.build(request);
    const engineDecision = await this.policyEngine.evaluate(context.input);
    const administratorDecision = this.policyAdministrator.prepare(
      engineDecision,
      context.input,
    );
    const decisionId = `pdp_${randomUUID()}`;
    const evaluatedAt = new Date().toISOString();
    const route = this.buildRoute(
      request,
      context,
      engineDecision,
      administratorDecision,
      decisionId,
      evaluatedAt,
    );

    const response: PdpResponse = {
      decisionId,
      requestId: context.requestId,
      evaluatedAt,
      decision: engineDecision.decision,
      reason: engineDecision.reason,
      route,
      context: {
        mode: context.mode,
        sources: context.sources,
        trace: context.trace,
        warnings: context.warnings,
        canonicalInput: context.input,
      },
      pe: {
        engine: engineDecision.engine,
        opaDecisionId: engineDecision.opaDecisionId,
        matchedPolicyId: engineDecision.policyId,
        matchedPolicyName: engineDecision.policyName,
        riskScore: engineDecision.riskScore,
      },
      pa: administratorDecision,
    };

    this.auditLog.recordDecision(response);

    return response;
  }

  private buildRoute(
    request: unknown,
    context: {
      requestId?: string;
      mode: string;
      input: AccessEvaluationInput;
      sources: unknown;
      trace: unknown;
      warnings: string[];
    },
    engineDecision: EngineDecision,
    administratorDecision: AdministratorDecision,
    decisionId: string,
    evaluatedAt: string,
  ): PdpRouteStep[] {
    return [
      {
        order: 1,
        stage: 'request_received',
        title: 'Request PDP API ga keldi',
        status: 'ok',
        description:
          'UI, curl, Postman yoki kelajakdagi PEP /pdp/evaluate endpointiga request yuboradi.',
        input: this.sanitizeRequest(request),
        process: {
          endpoint: 'POST /pdp/evaluate',
          requestId: context.requestId ?? null,
          acceptedFormats: ['evidence', 'canonical'],
        },
        output: {
          accepted: true,
          nextStage: 'context_builder',
        },
      },
      {
        order: 2,
        stage: 'context_builder',
        title: 'Context Builder requestni qabul qildi',
        status: 'ok',
        description:
          'Context Builder evidence/reference qiymatlarni source adapterlar orqali canonical JSON ga aylantirdi.',
        input: {
          mode: context.mode,
          request: this.sanitizeRequest(request),
        },
        process: {
          sources: context.sources,
          trace: context.trace,
          warnings: context.warnings,
        },
        output: {
          canonicalInput: context.input,
        },
      },
      {
        order: 3,
        stage: 'policy_engine',
        title: 'PE / OPA canonical JSON ni qabul qildi',
        status: 'ok',
        description:
          'OPA sentryx.zta/decision Rego rule orqali canonical inputni enterprise policy data bilan baholadi.',
        input: {
          canonicalInput: context.input,
        },
        process: {
          engine: 'opa',
          opaDecisionUrl: this.policyEngine.opaDecisionUrl,
          package: 'sentryx.zta',
          rule: 'decision',
          matchedPolicyId: engineDecision.policyId,
          opaDecisionId: engineDecision.opaDecisionId ?? null,
        },
        output: {
          decision: engineDecision.decision,
          policyId: engineDecision.policyId,
          policyName: engineDecision.policyName,
          riskScore: engineDecision.riskScore,
          reason: engineDecision.reason,
        },
      },
      {
        order: 4,
        stage: 'policy_administrator',
        title: 'PA PE qarorini qabul qildi',
        status: 'ok',
        description:
          'Policy Administrator allow/deny qarorini PEP bajaradigan permit/block instruction ga aylantirdi.',
        input: {
          engineDecision: {
            decision: engineDecision.decision,
            policyId: engineDecision.policyId,
            riskScore: engineDecision.riskScore,
            reason: engineDecision.reason,
          },
        },
        process: {
          mapping:
            engineDecision.decision === 'allow'
              ? 'allow -> permit'
              : 'deny -> block',
          ttlPolicy:
            engineDecision.decision === 'allow'
              ? 'risk score ga qarab 900/600/300 seconds'
              : 'deny uchun ttlSeconds 0',
          obligationsPolicy:
            engineDecision.decision === 'allow'
              ? 'audit + continuous monitoring + risk change revoke'
              : 'audit + return 403, high-risk bo‘lsa security notify',
        },
        output: administratorDecision,
      },
      {
        order: 5,
        stage: 'pdp_response',
        title: 'PDP final response qaytardi',
        status: 'ok',
        description:
          'PDP decision, Context Builder output, PE result, PA instruction va route trace ni clientga qaytardi.',
        process: {
          decisionId,
          evaluatedAt,
        },
        output: {
          decision: engineDecision.decision,
          enforcementCommand: administratorDecision.enforcementCommand,
          ttlSeconds: administratorDecision.ttlSeconds,
        },
      },
    ];
  }

  private sanitizeRequest(value: unknown): unknown {
    if (Array.isArray(value)) {
      return value.map((item) => this.sanitizeRequest(item));
    }

    if (typeof value !== 'object' || value === null) {
      return value;
    }

    const sanitized: Record<string, unknown> = {};

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
        sanitized[key] = this.sanitizeRequest(rawValue);
      }
    }

    return sanitized;
  }

  private mask(value: string): string {
    if (value.length <= 8) {
      return '***';
    }

    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }
}
