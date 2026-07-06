import { Injectable, Logger } from '@nestjs/common';
import { mkdirSync, appendFileSync, existsSync, readFileSync } from 'fs';
import { dirname } from 'path';
import { PdpResponse } from '../pdp.types';

export interface PdpAuditEvent {
  eventType: 'pdp.decision';
  decisionId: string;
  requestId?: string;
  evaluatedAt: string;
  subject: {
    user: string;
    role: string;
    department: string;
  };
  resource: {
    name: string;
    type: string;
    criticality: string;
  };
  action: string;
  decision: string;
  reason: string[];
  policy: {
    engine: 'opa';
    opaDecisionId?: string;
    matchedPolicyId: string;
    matchedPolicyName: string;
    riskScore: number;
  };
  enforcement: {
    command: string;
    ttlSeconds: number;
    obligations: string[];
  };
  context: {
    mode: string;
    sources: unknown;
    trace: unknown;
    warnings: string[];
  };
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);
  private readonly auditLogPath =
    process.env.PDP_AUDIT_LOG_PATH ??
    '/app/audit-logs/pdp-decisions.jsonl';

  recordDecision(response: PdpResponse): void {
    const event = this.toAuditEvent(response);
    const line = `${JSON.stringify(event)}\n`;

    try {
      mkdirSync(dirname(this.auditLogPath), { recursive: true });
      appendFileSync(this.auditLogPath, line, { encoding: 'utf8' });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to write PDP audit log: ${message}`);
    }
  }

  listRecent(limit = 20): {
    path: string;
    count: number;
    entries: PdpAuditEvent[];
  } {
    const safeLimit = Math.min(Math.max(Math.trunc(limit), 1), 100);

    if (!existsSync(this.auditLogPath)) {
      return {
        path: this.auditLogPath,
        count: 0,
        entries: [],
      };
    }

    const lines = readFileSync(this.auditLogPath, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');
    const entries = lines
      .slice(-safeLimit)
      .map((line) => this.parseLine(line))
      .filter((entry): entry is PdpAuditEvent => Boolean(entry))
      .reverse();

    return {
      path: this.auditLogPath,
      count: lines.length,
      entries,
    };
  }

  private parseLine(line: string): PdpAuditEvent | undefined {
    try {
      return JSON.parse(line) as PdpAuditEvent;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Skipping invalid audit log line: ${message}`);
      return undefined;
    }
  }

  private toAuditEvent(response: PdpResponse): PdpAuditEvent {
    const input = response.context.canonicalInput;

    return {
      eventType: 'pdp.decision',
      decisionId: response.decisionId,
      requestId: response.requestId,
      evaluatedAt: response.evaluatedAt,
      subject: {
        user: input.subject.user,
        role: input.subject.role,
        department: input.subject.department,
      },
      resource: {
        name: input.resource.name,
        type: input.resource.type,
        criticality: input.resource.criticality,
      },
      action: input.action,
      decision: response.decision,
      reason: response.reason,
      policy: {
        engine: response.pe.engine,
        opaDecisionId: response.pe.opaDecisionId,
        matchedPolicyId: response.pe.matchedPolicyId,
        matchedPolicyName: response.pe.matchedPolicyName,
        riskScore: response.pe.riskScore,
      },
      enforcement: {
        command: response.pa.enforcementCommand,
        ttlSeconds: response.pa.ttlSeconds,
        obligations: response.pa.obligations,
      },
      context: {
        mode: response.context.mode,
        sources: response.context.sources,
        trace: response.context.trace,
        warnings: response.context.warnings,
      },
    };
  }
}
