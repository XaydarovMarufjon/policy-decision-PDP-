const assert = require('node:assert/strict');
const test = require('node:test');
const { PdpService } = require('../dist/pdp/pdp.service');

function fixture(decision = 'allow') {
  const request = { request_id: 'fixture-request', action: 'read' };
  const input = {
    subject: { user: 'fixture-user', role: 'analyst', department: 'SOC', mfa: true },
    device: { managed: true, edr_status: 'healthy', patch_level: 'current', ip: '192.0.2.1' },
    risk: { siem_score: 12, threat_intel_match: false, impossible_travel: false },
    resource: { type: 'database', name: 'fixture-resource', criticality: 'high' },
    action: 'read',
  };
  const context = {
    requestId: request.request_id, mode: 'evidence', input,
    sources: { identity: 'fixture', device: 'fixture', risk: 'fixture', resource: 'fixture' },
    trace: [{ source: 'request', adapter: 'fixture', operation: 'read', lookupKey: 'fixture', status: 'ok', durationMs: 0, redacted: true }],
    warnings: ['synthetic warning'],
  };
  const engineDecision = {
    decision, policyId: 'fixture-policy', policyName: 'Fixture policy', riskScore: 37,
    reason: ['synthetic reason'], engine: 'opa', opaDecisionId: 'fixture-opa-id',
  };
  const administratorDecision = {
    enforcementCommand: decision === 'allow' ? 'permit' : 'block',
    ttlSeconds: decision === 'allow' ? 600 : 0, obligations: ['synthetic-obligation'],
  };
  const calls = [];
  const builder = { build: (value) => { calls.push(['build', value]); return context; } };
  const engine = {
    opaDecisionUrl: 'https://opa.invalid/fixture',
    evaluate: async (value) => { calls.push(['engine', value]); return engineDecision; },
  };
  const administrator = { prepare: (value, canonical) => {
    calls.push(['prepare', value, canonical]); return administratorDecision;
  } };
  const audit = { recordDecision: (value) => { calls.push(['audit', value]); } };
  return {
    service: new PdpService(builder, engine, administrator, audit),
    request, input, context, engineDecision, administratorDecision,
    builder, engine, administrator, audit, calls,
  };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

for (const decision of ['allow', 'deny']) {
  test(`${decision}: sequences collaborators with canonical input and audits the returned response once`, async () => {
    const f = fixture(decision);
    const before = structuredClone([f.request, f.context, f.engineDecision, f.administratorDecision]);
    const result = await f.service.evaluate(f.request);
    assert.deepEqual(f.calls.map(([stage]) => stage), ['build', 'engine', 'prepare', 'audit']);
    assert.strictEqual(f.calls[0][1], f.request);
    assert.strictEqual(f.calls[1][1], f.input);
    assert.strictEqual(f.calls[2][1], f.engineDecision);
    assert.strictEqual(f.calls[2][2], f.input);
    assert.strictEqual(f.calls[3][1], result);
    assert.deepEqual([f.request, f.context, f.engineDecision, f.administratorDecision], before);
    assert.equal(result.decision, decision);
    assert.deepEqual(result.reason, f.engineDecision.reason);
    assert.deepEqual(result.context, {
      mode: f.context.mode, sources: f.context.sources, trace: f.context.trace,
      warnings: f.context.warnings, canonicalInput: f.input,
    });
    assert.deepEqual(result.pe, {
      engine: 'opa', opaDecisionId: 'fixture-opa-id', matchedPolicyId: 'fixture-policy',
      matchedPolicyName: 'Fixture policy', riskScore: 37,
    });
    assert.deepEqual(result.pa, f.administratorDecision);
    assert.equal(result.requestId, 'fixture-request');
    assert.match(result.decisionId, /^pdp_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.equal(new Date(result.evaluatedAt).toISOString(), result.evaluatedAt);
  });

  test(`${decision}: route stages consistently describe the same decision and identifiers`, async () => {
    const f = fixture(decision);
    const result = await f.service.evaluate(f.request);
    const route = result.route;
    assert.deepEqual(route.map((step) => [step.order, step.stage, step.status]), [
      [1, 'request_received', 'ok'], [2, 'context_builder', 'ok'], [3, 'policy_engine', 'ok'],
      [4, 'policy_administrator', 'ok'], [5, 'pdp_response', 'ok'],
    ]);
    assert.deepEqual(route[0].input, f.request);
    assert.deepEqual(route[0].process, {
      endpoint: 'POST /pdp/evaluate', requestId: result.requestId, acceptedFormats: ['evidence', 'canonical'],
    });
    assert.deepEqual(route[1].input, { mode: f.context.mode, request: f.request });
    assert.deepEqual(route[1].process, { sources: f.context.sources, trace: f.context.trace, warnings: f.context.warnings });
    assert.deepEqual(route[1].output, { canonicalInput: f.input });
    assert.deepEqual(route[2].input, { canonicalInput: f.input });
    assert.equal(route[2].process.opaDecisionUrl, f.engine.opaDecisionUrl);
    assert.equal(route[2].process.matchedPolicyId, result.pe.matchedPolicyId);
    assert.equal(route[2].process.opaDecisionId, result.pe.opaDecisionId);
    assert.deepEqual(route[2].output, {
      decision, policyId: f.engineDecision.policyId, policyName: f.engineDecision.policyName,
      riskScore: result.pe.riskScore, reason: result.reason,
    });
    assert.deepEqual(route[3].input.engineDecision, {
      decision, policyId: f.engineDecision.policyId, riskScore: result.pe.riskScore, reason: result.reason,
    });
    assert.equal(route[3].process.mapping, decision === 'allow' ? 'allow -> permit' : 'deny -> block');
    assert.deepEqual(route[3].output, result.pa);
    assert.deepEqual(route[4].process, { decisionId: result.decisionId, evaluatedAt: result.evaluatedAt });
    assert.deepEqual(route[4].output, {
      decision, enforcementCommand: result.pa.enforcementCommand, ttlSeconds: result.pa.ttlSeconds,
    });
  });
}

test('passes through configured engine URL without caching it', () => {
  const f = fixture();
  assert.equal(f.service.opaDecisionUrl, f.engine.opaDecisionUrl);
  f.engine.opaDecisionUrl = 'https://opa.invalid/changed';
  assert.equal(f.service.opaDecisionUrl, f.engine.opaDecisionUrl);
});

test('supports canonical context and absent optional IDs without inventing them', async () => {
  const f = fixture();
  f.context.mode = 'canonical';
  delete f.context.requestId;
  delete f.engineDecision.opaDecisionId;
  f.context.warnings = [];
  f.context.trace = [];
  const result = await f.service.evaluate(f.request);
  assert.equal(result.context.mode, 'canonical');
  assert.equal(result.requestId, undefined);
  assert.equal(result.pe.opaDecisionId, undefined);
  assert.equal(result.route[0].process.requestId, null);
  assert.equal(result.route[2].process.opaDecisionId, null);
  assert.deepEqual(result.context.warnings, []);
  assert.deepEqual(result.context.trace, []);
});

test('does not prepare or audit until the policy engine resolves', async () => {
  const f = fixture();
  const gate = deferred();
  f.engine.evaluate = (input) => { f.calls.push(['engine', input]); return gate.promise; };
  const resultPromise = f.service.evaluate(f.request);
  assert.deepEqual(f.calls.map(([stage]) => stage), ['build', 'engine']);
  gate.resolve(f.engineDecision);
  await resultPromise;
  assert.deepEqual(f.calls.map(([stage]) => stage), ['build', 'engine', 'prepare', 'audit']);
});

for (const stage of ['build', 'engine', 'prepare', 'audit']) {
  test(`propagates ${stage} failure unchanged and stops downstream calls`, async () => {
    const f = fixture();
    const failure = new Error(`synthetic ${stage} failure`);
    const target = { build: f.builder, engine: f.engine, prepare: f.administrator, audit: f.audit }[stage];
    const method = { build: 'build', engine: 'evaluate', prepare: 'prepare', audit: 'recordDecision' }[stage];
    target[method] = (...args) => {
      f.calls.push([stage, ...args]);
      if (stage === 'engine') return Promise.reject(failure);
      throw failure;
    };
    await assert.rejects(f.service.evaluate(f.request), (error) => error === failure);
    assert.deepEqual(f.calls.map(([name]) => name), ['build', 'engine', 'prepare', 'audit'].slice(0, ['build', 'engine', 'prepare', 'audit'].indexOf(stage) + 1));
  });
}

test('keeps concurrent evaluations isolated when the second engine finishes first', async () => {
  const a = fixture('allow');
  const b = fixture('deny');
  b.request.request_id = 'second-request';
  b.context.requestId = 'second-request';
  b.input.subject.user = 'second-user';
  b.engineDecision.policyId = 'second-policy';
  const gates = [deferred(), deferred()];
  const audit = [];
  const service = new PdpService(
    { build: (request) => request === a.request ? a.context : b.context },
    { opaDecisionUrl: 'https://opa.invalid/fixture', evaluate: (input) => gates[input === a.input ? 0 : 1].promise },
    { prepare: (decision, input) => {
      assert.strictEqual(input, decision === a.engineDecision ? a.input : b.input);
      return decision === a.engineDecision ? a.administratorDecision : b.administratorDecision;
    } },
    { recordDecision: (result) => audit.push(result) },
  );
  const first = service.evaluate(a.request);
  const second = service.evaluate(b.request);
  gates[1].resolve(b.engineDecision);
  const resultB = await second;
  assert.deepEqual(audit, [resultB]);
  gates[0].resolve(a.engineDecision);
  const resultA = await first;
  assert.deepEqual(audit, [resultB, resultA]);
  assert.notEqual(resultA.decisionId, resultB.decisionId);
  for (const [result, f] of [[resultA, a], [resultB, b]]) {
    assert.equal(result.requestId, f.context.requestId);
    assert.deepEqual(result.context.canonicalInput, f.input);
    assert.equal(result.pe.matchedPolicyId, f.engineDecision.policyId);
    assert.deepEqual(result.pa, f.administratorDecision);
    assert.deepEqual(result.route[4].process, { decisionId: result.decisionId, evaluatedAt: result.evaluatedAt });
  }
});
