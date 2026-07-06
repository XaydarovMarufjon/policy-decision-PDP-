import { Injectable } from '@nestjs/common';
import {
  AccessEvaluationInput,
  AdministratorDecision,
  EngineDecision,
} from '../pdp.types';

@Injectable()
export class PolicyAdministratorService {
  prepare(
    engineDecision: EngineDecision,
    input: AccessEvaluationInput,
  ): AdministratorDecision {
    if (engineDecision.decision === 'allow') {
      return {
        enforcementCommand: 'permit',
        ttlSeconds: this.allowTtl(input.risk.siem_score),
        obligations: [
          'audit_decision',
          'continuous_monitoring_required',
          'revoke_access_if_risk_changes',
        ],
      };
    }

    return {
      enforcementCommand: 'block',
      ttlSeconds: 0,
      obligations: this.denyObligations(engineDecision),
    };
  }

  private allowTtl(riskScore: number): number {
    if (riskScore >= 50) {
      return 300;
    }

    if (riskScore >= 30) {
      return 600;
    }

    return 900;
  }

  private denyObligations(engineDecision: EngineDecision): string[] {
    const obligations = ['audit_decision', 'return_403_to_pep'];

    if (
      engineDecision.policyId === 'policy-deny-high-risk' ||
      engineDecision.policyId === 'policy-deny-threat-intel-match' ||
      engineDecision.policyId === 'policy-deny-impossible-travel'
    ) {
      obligations.push('notify_security_team');
    }

    return obligations;
  }
}
