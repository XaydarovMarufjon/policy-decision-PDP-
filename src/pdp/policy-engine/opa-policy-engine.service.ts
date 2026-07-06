import { BadGatewayException, Injectable } from '@nestjs/common';
import { AccessEvaluationInput, EngineDecision } from '../pdp.types';
import { PolicyEngine } from './policy-engine.interface';

interface OpaDecisionResult {
  decision?: 'allow' | 'deny';
  policyId?: string;
  policyName?: string;
  reason?: string[];
  riskScore?: number;
}

interface OpaResponse {
  decision_id?: string;
  result?: OpaDecisionResult;
}

@Injectable()
export class OpaPolicyEngineService implements PolicyEngine {
  readonly opaDecisionUrl =
    process.env.OPA_DECISION_URL ??
    'http://localhost:8181/v1/data/sentryx/zta/decision';

  async evaluate(input: AccessEvaluationInput): Promise<EngineDecision> {
    let response: Response;

    try {
      response = await fetch(this.opaDecisionUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input }),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new BadGatewayException(`OPA request failed: ${message}`);
    }

    if (!response.ok) {
      throw new BadGatewayException(
        `OPA request failed with status ${response.status}`,
      );
    }

    const body = (await response.json()) as OpaResponse;

    if (!body.result?.decision) {
      throw new BadGatewayException(
        'OPA response does not contain result.decision',
      );
    }

    return {
      decision: body.result.decision,
      policyId: body.result.policyId ?? 'unknown-policy',
      policyName: body.result.policyName ?? 'Unknown policy',
      riskScore: body.result.riskScore ?? input.risk.siem_score,
      reason: body.result.reason ?? ['OPA returned no reason'],
      engine: 'opa',
      opaDecisionId: body.decision_id,
    };
  }
}
