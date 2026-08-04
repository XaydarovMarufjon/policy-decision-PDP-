import { Injectable, Logger } from '@nestjs/common';
import {
  mkdirSync,
  existsSync,
  statSync,
  openSync,
  readSync,
  closeSync,
} from 'fs';
import { appendFile, rename, stat } from 'fs/promises';
import { dirname } from 'path';
import { createHmac } from 'crypto';
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
  route: Array<{
    order: number;
    stage: string;
    title: string;
    status: string;
    description: string;
  }>;
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
  integrityHmac?: string;
}

@Injectable()
export class AuditLogService {
  private readonly logger = new Logger(AuditLogService.name);
  private readonly auditLogPath =
    process.env.PDP_AUDIT_LOG_PATH ??
    '/app/audit-logs/pdp-decisions.jsonl';
  // Only the trailing slice of the (append-only, unbounded) log is read per
  // request, so a large log never blocks the event loop or loads fully into
  // memory. NOTE: the write path is still synchronous appendFileSync and there
  // is no rotation yet — follow-up: size-based rotation inside /app/audit-logs.
  private readonly tailBytes = Math.max(
    4096,
    Number(process.env.PDP_AUDIT_TAIL_BYTES ?? 65536),
  );
  private readonly maxBytes = this.positiveNumber(
    process.env.PDP_AUDIT_MAX_BYTES,
    10 * 1024 * 1024,
  );
  private readonly required = process.env.PDP_AUDIT_REQUIRED === 'true';
  private readonly webhookUrl = process.env.PDP_AUDIT_WEBHOOK_URL;
  private readonly webhookTimeoutMs = this.positiveNumber(
    process.env.PDP_AUDIT_WEBHOOK_TIMEOUT_MS,
    2000,
  );
  private readonly hmacSecret = process.env.PDP_AUDIT_HMAC_SECRET;
  private writeQueue: Promise<void> = Promise.resolve();

  recordDecision(response: PdpResponse): Promise<void> {
    const event = this.signEvent(this.toAuditEvent(response));
    const line = `${JSON.stringify(event)}\n`;
    const operation = this.writeQueue.then(() => this.writeLine(line));
    // Keep the queue usable after a failed operation.
    this.writeQueue = operation.catch(() => undefined);
    return operation;
  }

  private async writeLine(line: string): Promise<void> {
    try {
      mkdirSync(dirname(this.auditLogPath), { recursive: true });
      await this.rotateIfNeeded(Buffer.byteLength(line));
      await appendFile(this.auditLogPath, line, { encoding: 'utf8' });
      await this.forwardToWebhook(line);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Failed to write PDP audit log: ${message}`);
      if (this.required) throw error;
    }
  }

  private signEvent(event: PdpAuditEvent): PdpAuditEvent {
    if (!this.hmacSecret) return event;
    return {
      ...event,
      integrityHmac: createHmac('sha256', this.hmacSecret)
        .update(JSON.stringify(event))
        .digest('hex'),
    };
  }

  private async forwardToWebhook(line: string): Promise<void> {
    if (!this.webhookUrl) return;
    const response = await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: line.trimEnd(),
      signal: AbortSignal.timeout(this.webhookTimeoutMs),
    });
    if (!response.ok) {
      throw new Error(`Audit webhook returned HTTP ${response.status}`);
    }
  }

  private async rotateIfNeeded(incomingBytes: number): Promise<void> {
    try {
      const info = await stat(this.auditLogPath);
      if (info.size + incomingBytes < this.maxBytes) return;
      const rotated = `${this.auditLogPath}.${new Date().toISOString().replace(/[:.]/g, '-')}`;
      await rename(this.auditLogPath, rotated);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') throw error;
    }
  }

  private positiveNumber(value: string | undefined, fallback: number): number {
    const parsed = Number(value ?? fallback);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error('Audit size/timeout settings must be positive numbers');
    }
    return parsed;
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

    const lines = this.readTailLines();
    const entries = lines
      .slice(-safeLimit)
      .map((line) => this.parseLine(line))
      .filter((entry): entry is PdpAuditEvent => Boolean(entry))
      .reverse();

    return {
      path: this.auditLogPath,
      // Bounded read: this is the count within the tail window, not the whole
      // file. The console shows it as an approximate recent-events chip.
      count: lines.length,
      entries,
    };
  }

  /** Read only the last `tailBytes` of the log and return its complete lines. */
  private readTailLines(): string[] {
    const size = statSync(this.auditLogPath).size;
    if (size === 0) {
      return [];
    }

    const readBytes = Math.min(size, this.tailBytes);
    const offset = size - readBytes;
    const buffer = Buffer.allocUnsafe(readBytes);

    const fd = openSync(this.auditLogPath, 'r');
    try {
      readSync(fd, buffer, 0, readBytes, offset);
    } finally {
      closeSync(fd);
    }

    const lines = buffer
      .toString('utf8')
      .split('\n')
      .filter((line) => line.trim() !== '');

    // When we started mid-file, the first line is likely a partial record.
    if (offset > 0 && lines.length > 0) {
      lines.shift();
    }

    return lines;
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
      route: response.route.map((step) => ({
        order: step.order,
        stage: step.stage,
        title: step.title,
        status: step.status,
        description: step.description,
      })),
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
