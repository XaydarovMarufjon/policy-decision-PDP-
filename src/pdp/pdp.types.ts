export type Decision = 'allow' | 'deny';
export type EnforcementCommand = 'permit' | 'block';
export type ContextBuildMode = 'canonical' | 'evidence';

export interface SubjectContext {
  user: string;
  role: string;
  department: string;
  mfa: boolean;
}

export interface DeviceContext {
  managed: boolean;
  edr_status: string;
  patch_level: string;
  ip: string;
}

export interface RiskContext {
  siem_score: number;
  threat_intel_match: boolean;
  impossible_travel: boolean;
}

export interface ResourceContext {
  type: string;
  name: string;
  criticality: string;
}

export interface AccessEvaluationInput {
  subject: SubjectContext;
  device: DeviceContext;
  risk: RiskContext;
  resource: ResourceContext;
  action: string;
}

export interface SubjectRef {
  type: 'jwt' | 'mock_token' | 'user_id';
  token?: string;
  user_id?: string;
  session_id?: string;
  user_agent?: string;
}

export interface DeviceEvidence {
  device_id?: string;
  hostname?: string;
  agent_id?: string;
  os?: string;
  os_version?: string;
  browser?: string;
  certificate_fingerprint?: string;
}

export interface NetworkEvidence {
  source_ip?: string;
  source_port?: number;
  protocol?: string;
  geo_country?: string;
  network_zone?: string;
}

export interface ResourceRef {
  resource_id: string;
  path?: string;
  environment?: string;
  tenant_id?: string;
  sensitivity_hint?: string;
}

export interface RiskEvidence extends Partial<RiskContext> {
  alert_ids?: string[];
  source?: string;
  risk_reason?: string;
}

export interface EvidenceEvaluationRequest {
  request_id?: string;
  request_metadata?: Record<string, unknown>;
  subject_ref: SubjectRef;
  device_evidence: DeviceEvidence;
  network?: NetworkEvidence;
  resource_ref: ResourceRef;
  risk_evidence?: RiskEvidence;
  action: string;
}

export interface ContextSources {
  identity: string;
  device: string;
  risk: string;
  resource: string;
}

export type ContextTraceStatus = 'ok' | 'miss' | 'error' | 'skipped';

export interface ContextTraceEntry {
  source: 'request' | 'identity' | 'device' | 'risk' | 'resource';
  adapter: string;
  operation: string;
  lookupKey: string;
  status: ContextTraceStatus;
  durationMs: number;
  redacted: boolean;
  result?: unknown;
  error?: string;
}

export interface ContextBuildResult {
  requestId?: string;
  mode: ContextBuildMode;
  input: AccessEvaluationInput;
  sources: ContextSources;
  trace: ContextTraceEntry[];
  warnings: string[];
}

export interface EngineDecision {
  decision: Decision;
  policyId: string;
  policyName: string;
  riskScore: number;
  reason: string[];
  engine: 'opa';
  opaDecisionId?: string;
}

export interface AdministratorDecision {
  enforcementCommand: EnforcementCommand;
  ttlSeconds: number;
  obligations: string[];
}

export interface PdpResponse {
  decisionId: string;
  requestId?: string;
  evaluatedAt: string;
  decision: Decision;
  reason: string[];
  route: PdpRouteStep[];
  context: {
    mode: ContextBuildMode;
    sources: ContextSources;
    trace: ContextTraceEntry[];
    warnings: string[];
    canonicalInput: AccessEvaluationInput;
  };
  pe: {
    engine: 'opa';
    opaDecisionId?: string;
    matchedPolicyId: string;
    matchedPolicyName: string;
    riskScore: number;
  };
  pa: AdministratorDecision;
}

export interface PdpRouteStep {
  order: number;
  stage:
    | 'request_received'
    | 'context_builder'
    | 'policy_engine'
    | 'policy_administrator'
    | 'pdp_response';
  title: string;
  status: 'ok' | 'error';
  description: string;
  input?: unknown;
  process: unknown;
  output?: unknown;
}
