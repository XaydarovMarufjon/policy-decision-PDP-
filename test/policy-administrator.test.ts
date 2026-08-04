import assert from 'node:assert/strict';
import test from 'node:test';
import { PolicyAdministratorService } from '../src/pdp/policy-administrator/policy-administrator.service';
import { AccessEvaluationInput, EngineDecision } from '../src/pdp/pdp.types';

const input = (risk: number): AccessEvaluationInput => ({
  subject: { user: 'u', role: 'analyst', department: 'SOC', mfa: true },
  device: { managed: true, edr_status: 'healthy', patch_level: 'current', ip: '127.0.0.1' },
  risk: { siem_score: risk, threat_intel_match: false, impossible_travel: false },
  resource: { type: 'database', name: 'incident_db', criticality: 'high' },
  action: 'read',
});

const decision = (value: 'allow' | 'deny', policyId = 'p'): EngineDecision => ({
  decision: value,
  policyId,
  policyName: policyId,
  riskScore: 0,
  reason: [],
  engine: 'opa',
});

test('allow TTL decreases as risk rises', () => {
  const service = new PolicyAdministratorService();
  assert.equal(service.prepare(decision('allow'), input(10)).ttlSeconds, 900);
  assert.equal(service.prepare(decision('allow'), input(30)).ttlSeconds, 600);
  assert.equal(service.prepare(decision('allow'), input(50)).ttlSeconds, 300);
});

test('deny fails closed and escalates security policies', () => {
  const service = new PolicyAdministratorService();
  const result = service.prepare(
    decision('deny', 'policy-deny-high-risk'),
    input(90),
  );
  assert.equal(result.enforcementCommand, 'block');
  assert.equal(result.ttlSeconds, 0);
  assert.ok(result.obligations.includes('notify_security_team'));
});
