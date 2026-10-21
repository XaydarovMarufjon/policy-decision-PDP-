const assert = require('node:assert/strict');
const { test } = require('node:test');
const { BadGatewayException } = require('@nestjs/common');
const { OpaPolicyEngineService } = require('../dist/pdp/policy-engine/opa-policy-engine.service');

function input() {
  return {
    subject: { user: 'synthetic-user', role: 'analyst', department: 'SOC', mfa: true },
    device: { managed: true, edr_status: 'healthy', patch_level: 'current', ip: '127.0.0.1' },
    risk: { siem_score: 42, threat_intel_match: false, impossible_travel: false },
    resource: { type: 'database', name: 'synthetic-db', criticality: 'high' },
    action: 'read',
  };
}

function fixture(t, reply, url) {
  const previous = process.env.OPA_DECISION_URL;
  let service;
  try {
    if (url === undefined) delete process.env.OPA_DECISION_URL;
    else process.env.OPA_DECISION_URL = url;
    service = new OpaPolicyEngineService();
  } finally {
    if (previous === undefined) delete process.env.OPA_DECISION_URL;
    else process.env.OPA_DECISION_URL = previous;
  }
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (...args) => {
    calls.push(args);
    return typeof reply === 'function' ? reply(...args) : reply;
  });
  return { service, calls };
}

function json(body) {
  return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
}

function gateway(message) {
  return (error) => {
    assert.ok(error instanceof BadGatewayException);
    assert.equal(error.getStatus(), 502);
    assert.equal(error.message, message);
    return true;
  };
}

test('POSTs one canonical input envelope to the default OPA endpoint without mutating it', async (t) => {
  const { service, calls } = fixture(t, json({ result: { decision: 'allow' } }));
  const request = input();
  const before = structuredClone(request);
  await service.evaluate(request);
  assert.deepEqual(calls, [['http://localhost:8181/v1/data/sentryx/zta/decision', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: request }),
  }]]);
  assert.deepEqual(request, before);
});

test('uses the configured endpoint captured when the adapter is constructed', async (t) => {
  const { service, calls } = fixture(t, json({ result: { decision: 'deny' } }), 'http://opa.test/custom');
  await service.evaluate(input());
  assert.equal(calls[0][0], 'http://opa.test/custom');
});

for (const decision of ['allow', 'deny']) {
  test(`maps a complete ${decision} response and OPA decision ID`, async (t) => {
    const result = { decision, policyId: 'policy-test', policyName: 'Synthetic policy', riskScore: 73, reason: ['one', 'two'] };
    const { service } = fixture(t, json({ decision_id: 'opa-test-id', result }));
    assert.deepEqual(await service.evaluate(input()), { ...result, engine: 'opa', opaDecisionId: 'opa-test-id' });
  });
}

for (const missing of [undefined, null]) {
  test(`defaults optional response fields when ${String(missing)}`, async (t) => {
    const { service } = fixture(t, json({ result: {
      decision: 'deny', policyId: missing, policyName: missing, riskScore: missing, reason: missing,
    } }));
    assert.deepEqual(await service.evaluate(input()), {
      decision: 'deny', policyId: 'unknown-policy', policyName: 'Unknown policy',
      riskScore: 42, reason: ['OPA returned no reason'], engine: 'opa', opaDecisionId: undefined,
    });
  });
}

test('preserves explicit zero risk, empty reasons and empty policy labels', async (t) => {
  const { service } = fixture(t, json({ result: {
    decision: 'allow', riskScore: 0, reason: [], policyId: '', policyName: '',
  } }));
  assert.deepEqual(await service.evaluate(input()), {
    decision: 'allow', riskScore: 0, reason: [], policyId: '', policyName: '', engine: 'opa', opaDecisionId: undefined,
  });
});

for (const status of [400, 403, 500, 503]) {
  test(`rejects HTTP ${status} without parsing its response body or retrying`, async (t) => {
    let parsed = false;
    const { service, calls } = fixture(t, { ok: false, status, json() { parsed = true; throw new Error('must not parse'); } });
    await assert.rejects(service.evaluate(input()), gateway(`OPA request failed with status ${status}`));
    assert.equal(parsed, false);
    assert.equal(calls.length, 1);
  });
}

for (const reason of [new Error('synthetic outage'), 'synthetic rejection']) {
  test(`normalizes ${reason instanceof Error ? 'Error' : 'non-Error'} fetch failures to 502 without retrying`, async (t) => {
    const { service, calls } = fixture(t, () => { throw reason; });
    await assert.rejects(service.evaluate(input()), gateway(`OPA request failed: ${reason instanceof Error ? reason.message : reason}`));
    assert.equal(calls.length, 1);
  });
}

for (const body of [{}, { result: null }, { result: {} }, { result: { decision: '' } }]) {
  test(`rejects a response without a decision: ${JSON.stringify(body)}`, async (t) => {
    const { service } = fixture(t, json(body));
    await assert.rejects(service.evaluate(input()), gateway('OPA response does not contain result.decision'));
  });
}

test('keeps simultaneous response mappings associated with their own request', async (t) => {
  const pending = [];
  const { service, calls } = fixture(t, () => new Promise((resolve) => pending.push(resolve)));
  const firstInput = input();
  const secondInput = input();
  secondInput.risk.siem_score = 17;
  const first = service.evaluate(firstInput);
  const second = service.evaluate(secondInput);
  pending[1](json({ decision_id: 'second', result: { decision: 'deny' } }));
  const secondResult = await second;
  pending[0](json({ decision_id: 'first', result: { decision: 'allow' } }));
  const firstResult = await first;
  assert.equal(firstResult.opaDecisionId, 'first');
  assert.equal(firstResult.decision, 'allow');
  assert.equal(firstResult.riskScore, 42);
  assert.equal(secondResult.opaDecisionId, 'second');
  assert.equal(secondResult.decision, 'deny');
  assert.equal(secondResult.riskScore, 17);
  assert.equal(calls.length, 2);
});
