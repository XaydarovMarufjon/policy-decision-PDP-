const assert = require('node:assert/strict');
const { test } = require('node:test');
const { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, mkdirSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { AuditLogService } = require('../dist/pdp/audit/audit-log.service');

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'pdp-audit-test-'));
  const path = join(directory, 'nested', 'decisions.jsonl');
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const previous = process.env.PDP_AUDIT_LOG_PATH;
  let service;
  try {
    process.env.PDP_AUDIT_LOG_PATH = path;
    service = new AuditLogService();
  } finally {
    if (previous === undefined) delete process.env.PDP_AUDIT_LOG_PATH;
    else process.env.PDP_AUDIT_LOG_PATH = previous;
  }
  const errors = [];
  const warnings = [];
  // Instance-local logger interception: never silence application/global logging.
  service.logger = { error: (message) => errors.push(message), warn: (message) => warnings.push(message) };
  return { service, directory, path, errors, warnings };
}

function response(id = 'decision-1') {
  return {
    decisionId: id, requestId: 'request-1', evaluatedAt: '2026-10-19T00:00:00.000Z',
    decision: 'deny', reason: ['Risk above threshold'],
    route: [{ input: { token: 'synthetic-route-token' } }],
    context: {
      mode: 'evidence',
      sources: { identity: 'mock', device: 'mock', risk: 'mock', resource: 'mock' },
      trace: [{ source: 'identity', adapter: 'mock', operation: 'lookup', lookupKey: '[redacted]', status: 'ok', durationMs: 0, redacted: true }],
      warnings: ['Synthetic warning'],
      canonicalInput: {
        subject: { user: 'Zoë', role: 'analyst', department: 'SOC', mfa: true, extra: 'subject-extra' },
        device: { managed: true, edr_status: 'healthy', patch_level: 'current', ip: '192.0.2.1' },
        risk: { siem_score: 85, threat_intel_match: false, impossible_travel: false },
        resource: { name: 'incidents', type: 'database', criticality: 'high', extra: 'resource-extra' },
        action: 'read',
      },
    },
    pe: { engine: 'opa', opaDecisionId: 'opa-1', matchedPolicyId: 'risk-deny', matchedPolicyName: 'High risk', riskScore: 85, extra: 'pe-extra' },
    pa: { enforcementCommand: 'block', ttlSeconds: 0, obligations: ['notify'], extra: 'pa-extra' },
    token: 'synthetic-top-level-token',
  };
}

function expectedEvent(id = 'decision-1') {
  return {
    eventType: 'pdp.decision', decisionId: id, requestId: 'request-1', evaluatedAt: '2026-10-19T00:00:00.000Z',
    subject: { user: 'Zoë', role: 'analyst', department: 'SOC' },
    resource: { name: 'incidents', type: 'database', criticality: 'high' },
    action: 'read', decision: 'deny', reason: ['Risk above threshold'],
    policy: { engine: 'opa', opaDecisionId: 'opa-1', matchedPolicyId: 'risk-deny', matchedPolicyName: 'High risk', riskScore: 85 },
    enforcement: { command: 'block', ttlSeconds: 0, obligations: ['notify'] },
    context: {
      mode: 'evidence', sources: { identity: 'mock', device: 'mock', risk: 'mock', resource: 'mock' },
      trace: [{ source: 'identity', adapter: 'mock', operation: 'lookup', lookupKey: '[redacted]', status: 'ok', durationMs: 0, redacted: true }],
      warnings: ['Synthetic warning'],
    },
  };
}

function seed(f, lines) {
  mkdirSync(join(f.directory, 'nested'), { recursive: true });
  writeFileSync(f.path, lines, 'utf8');
}

test('missing audit file returns an empty result without creating directories', (t) => {
  const f = fixture(t);
  assert.deepEqual(f.service.listRecent(), { path: f.path, count: 0, entries: [] });
  assert.equal(existsSync(join(f.directory, 'nested')), false);
});

test('records the exact projected event as newline-terminated UTF-8 JSONL without mutating input', (t) => {
  const f = fixture(t);
  const input = response();
  const before = structuredClone(input);
  f.service.recordDecision(input);
  assert.equal(readFileSync(f.path, 'utf8'), `${JSON.stringify(expectedEvent())}\n`);
  assert.deepEqual(input, before);
  assert.deepEqual(f.errors, []);
});

test('omits absent optional request and OPA decision identifiers', (t) => {
  const f = fixture(t);
  const input = response();
  delete input.requestId;
  delete input.pe.opaDecisionId;
  f.service.recordDecision(input);
  const expected = expectedEvent();
  delete expected.requestId;
  delete expected.policy.opaDecisionId;
  assert.deepEqual(JSON.parse(readFileSync(f.path, 'utf8')), expected);
});

test('appends rather than overwrites and returns newest appended record first', (t) => {
  const f = fixture(t);
  const first = response('first');
  first.evaluatedAt = '2030-01-01T00:00:00.000Z';
  f.service.recordDecision(first);
  const original = readFileSync(f.path, 'utf8');
  f.service.recordDecision(response('second'));
  assert.ok(readFileSync(f.path, 'utf8').startsWith(original));
  const result = f.service.listRecent();
  assert.equal(result.path, f.path);
  assert.equal(result.count, 2);
  assert.deepEqual(result.entries.map((entry) => entry.decisionId), ['second', 'first']);
});

for (const [name, contents] of [['empty', ''], ['whitespace-only', '\n \t\n\r\n']]) {
  test(`${name} files return no records`, (t) => {
    const f = fixture(t);
    seed(f, contents);
    assert.deepEqual(f.service.listRecent(), { path: f.path, count: 0, entries: [] });
    assert.deepEqual(f.warnings, []);
  });
}

test('reads CRLF, blank separators, and a final record without a newline', (t) => {
  const f = fixture(t);
  seed(f, `\r\n${JSON.stringify(expectedEvent('first'))}\r\n \t\n${JSON.stringify(expectedEvent('last'))}`);
  assert.equal(f.service.listRecent().count, 2);
  assert.deepEqual(f.service.listRecent().entries, [expectedEvent('last'), expectedEvent('first')]);
});

for (const [name, limit, expectedLength] of [
  ['default', undefined, 20], ['explicit', 3, 3], ['fractional', 3.9, 3],
  ['zero', 0, 1], ['negative', -7, 1], ['maximum', 100, 100], ['over maximum', 150, 100],
]) {
  test(`${name} limit selects the bounded trailing records while count includes all lines`, (t) => {
    const f = fixture(t);
    seed(f, Array.from({ length: 105 }, (_, i) => JSON.stringify(expectedEvent(`decision-${i}`))).join('\n'));
    const result = f.service.listRecent(limit);
    assert.equal(result.count, 105);
    assert.deepEqual(result.entries.map((entry) => entry.decisionId),
      Array.from({ length: expectedLength }, (_, i) => `decision-${104 - i}`));
  });
}

test('skips malformed selected lines, warns, and does not backfill outside the requested window', (t) => {
  const f = fixture(t);
  seed(f, [JSON.stringify(expectedEvent('older')), '{broken-json', JSON.stringify(expectedEvent('latest'))].join('\n'));
  const result = f.service.listRecent(2);
  assert.equal(result.count, 3);
  assert.deepEqual(result.entries, [expectedEvent('latest')]);
  assert.equal(f.warnings.length, 1);
  assert.match(f.warnings[0], /^Skipping invalid audit log line: /);
});

test('does not parse or warn about malformed lines outside the selected window', (t) => {
  const f = fixture(t);
  seed(f, `{broken-json\n${JSON.stringify(expectedEvent())}\n`);
  assert.deepEqual(f.service.listRecent(1).entries, [expectedEvent()]);
  assert.deepEqual(f.warnings, []);
});

test('logs directory-creation failures without throwing or creating an audit file', (t) => {
  const f = fixture(t);
  writeFileSync(join(f.directory, 'nested'), 'parent-is-a-file');
  assert.doesNotThrow(() => f.service.recordDecision(response()));
  assert.equal(f.errors.length, 1);
  assert.match(f.errors[0], /^Failed to write PDP audit log: /);
  assert.equal(readFileSync(join(f.directory, 'nested'), 'utf8'), 'parent-is-a-file');
});

test('logs append failures and can record again after the obstruction is removed', (t) => {
  const f = fixture(t);
  mkdirSync(f.path, { recursive: true });
  assert.doesNotThrow(() => f.service.recordDecision(response('failed')));
  assert.equal(f.errors.length, 1);
  assert.match(f.errors[0], /^Failed to write PDP audit log: /);
  rmSync(f.path, { recursive: true });
  f.service.recordDecision(response('recovered'));
  assert.deepEqual(f.service.listRecent().entries, [expectedEvent('recovered')]);
  assert.equal(f.errors.length, 1);
});
