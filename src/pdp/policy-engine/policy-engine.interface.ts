import { AccessEvaluationInput, EngineDecision } from '../pdp.types';

export interface PolicyEngine {
  evaluate(input: AccessEvaluationInput): Promise<EngineDecision>;
}
