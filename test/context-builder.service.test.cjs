const assert = require('node:assert/strict');
const test = require('node:test');
const { BadRequestException } = require('@nestjs/common');
const { ContextBuilderService } = require('../dist/pdp/context/context-builder.service');

function canonical() {
  return {
    subject: { user: 'fixture-user', role: 'analyst', department: 'SOC', mfa: false },
    device: { managed: false, edr_status: 'healthy', patch_level: 'current', ip: '192.0.2.1' },
    risk: { siem_score: 0, threat_intel_match: false, impossible_travel: false },
    resource: { type: 'database', name: 'fixture-resource', criticality: 'high' },
    action: 'read',
  };
}

function evidence() {
  return {
    request_id: 'fixture-request',
    subject_ref: { type: 'user_id', user_id: 'fixture-user' },
    device_evidence: { device_id: 'fixture-device' },
    resource_ref: { resource_id: 'fixture-resource' },
    network: { source_ip: '198.51.100.2' },
    action: 'read',
  };
}

// A fresh double per test isolates orchestration from repository/file-loading tests.
function fixture(overrides = {}) {
  const data = canonical();
  data.risk = { siem_score: 70, threat_intel_match: true, impossible_travel: true };
  const calls = [];
  const sources = {};
  for (const [method, field] of [
    ['resolveSubject', 'subject'], ['resolveDevice', 'device'],
    ['resolveResource', 'resource'], ['resolveRisk', 'risk'],
  ]) {
    sources[method] = (argument) => {
      calls.push([method, argument]);
      return Object.hasOwn(overrides, method) ? overrides[method](argument) : data[field];
    };
  }
  return { service: new ContextBuilderService(sources), data, calls };
}

function rejectsBuild(service, request, message) {
  assert.throws(() => service.build(request), (error) => {
    assert.ok(error instanceof BadRequestException);
    assert.equal(error.getStatus(), 400);
    if (message) assert.equal(error.message, message);
    return true;
  });
}

test('canonical input copies only declared fields without consulting sources', () => {
  const { service, calls } = fixture();
  const input = canonical();
  input.subject.user = ' fixture-user ';
  const request = structuredClone(input);
  request.request_id = 'fixture-request';
  request.subject.extra = 'ignored';
  request.extra = 'ignored';
  const before = structuredClone(request);
  const result = service.build(request);
  assert.equal(result.mode, 'canonical');
  assert.equal(result.requestId, 'fixture-request');
  assert.deepEqual(result.input, input);
  assert.deepEqual(calls, []);
  assert.deepEqual(request, before);
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /bypassed mock source enrichment/);
  for (const [index, field] of ['subject', 'device', 'risk', 'resource'].entries()) {
    const source = field === 'subject' ? 'identity' : field;
    assert.equal(result.sources[source], `request.${field}`);
    assert.deepEqual(result.trace[index], {
      source: 'request', adapter: 'manual-json', operation: source,
      lookupKey: `request.${field}`, status: 'ok', durationMs: 0,
      redacted: false, result: input[field],
    });
  }
  assert.equal(result.trace.length, 4);
});

for (const mode of ['canonical', 'evidence']) {
  test(`${mode} omits blank/non-string request IDs and preserves nonblank IDs`, () => {
    const { service } = fixture();
    for (const value of [undefined, null, '', '  ', 12]) {
      const request = mode === 'canonical' ? canonical() : evidence();
      request.request_id = value;
      assert.equal(service.build(request).requestId, undefined);
    }
    const request = mode === 'canonical' ? canonical() : evidence();
    request.request_id = ' id ';
    assert.equal(service.build(request).requestId, ' id ');
  });
}

test('rejects non-object bodies and incomplete request shapes before source lookup', () => {
  const { service, calls } = fixture();
  for (const value of [undefined, null, [], 'request', 1, false]) {
    rejectsBuild(service, value, 'request body must be an object');
  }
  for (const makeRequest of [canonical, evidence]) {
    for (const field of Object.keys(makeRequest()).filter((key) => !['request_id', 'network'].includes(key))) {
      const request = makeRequest();
      delete request[field];
      rejectsBuild(service, request);
    }
  }
  assert.deepEqual(calls, []);
});

const stringFields = [
  'subject.user', 'subject.role', 'subject.department', 'device.edr_status',
  'device.patch_level', 'device.ip', 'resource.type', 'resource.name',
  'resource.criticality', 'action',
];
const booleanFields = [
  'subject.mfa', 'device.managed', 'risk.threat_intel_match', 'risk.impossible_travel',
];
for (const [fields, invalid, suffix] of [
  [stringFields, [undefined, '', '  ', 1, false], 'a non-empty string'],
  [booleanFields, [undefined, 'false', 0, null], 'a boolean'],
  [['risk.siem_score'], [undefined, '0', NaN, Infinity, -Infinity, null], 'a finite number'],
]) {
  for (const field of fields) {
    test(`canonical validates ${field}`, () => {
      const { service, calls } = fixture();
      for (const value of invalid) {
        const request = canonical();
        const parts = field.split('.');
        const target = parts.length === 1 ? request : request[parts[0]];
        target[parts.at(-1)] = value;
        // Non-string actions fail format selection before field validation.
        rejectsBuild(service, request, field === 'action' && typeof value !== 'string'
          ? undefined : `${field} must be ${suffix}`);
      }
      assert.deepEqual(calls, []);
    });
  }
}

test('evidence routes exact lookup arguments and builds context without mutating inputs', () => {
  const { service, data, calls } = fixture();
  const request = evidence();
  const beforeRequest = structuredClone(request);
  const beforeData = structuredClone(data);
  const result = service.build(request);
  assert.equal(result.mode, 'evidence');
  assert.equal(result.requestId, request.request_id);
  assert.deepEqual(result.input, { ...data, device: { ...data.device, ip: request.network.source_ip } });
  assert.deepEqual(calls, [
    ['resolveSubject', request.subject_ref], ['resolveDevice', 'fixture-device'],
    ['resolveResource', 'fixture-resource'], ['resolveRisk', '198.51.100.2'],
  ]);
  assert.deepEqual(result.sources, {
    identity: 'mock-sources/identity.json:user_id', device: 'mock-sources/devices.json:fixture-device',
    resource: 'mock-sources/resources.json:fixture-resource', risk: 'mock-sources/risks.json:198.51.100.2',
  });
  assert.deepEqual(result.warnings, []);
  assert.deepEqual(result.trace.map((entry) => entry.operation), [
    'subject_ref', 'device_evidence', 'network', 'resource_ref',
    'resolve_subject', 'resolve_device', 'resolve_resource', 'resolve_risk',
  ]);
  for (const entry of result.trace) {
    assert.equal(entry.status, 'ok');
    assert.equal(entry.redacted, true);
    assert.ok(Number.isInteger(entry.durationMs) && entry.durationMs >= 0);
  }
  assert.deepEqual(request, beforeRequest);
  assert.deepEqual(data, beforeData);
});

test('missing network preserves device IP and uses the default risk lookup', () => {
  const { service, data, calls } = fixture();
  const request = evidence();
  delete request.network;
  const result = service.build(request);
  assert.deepEqual(result.input.device, data.device);
  assert.deepEqual(calls.at(-1), ['resolveRisk', undefined]);
  assert.equal(result.sources.risk, 'mock-sources/risks.json:default');
  assert.equal(result.trace.at(-1).lookupKey, 'default');
  assert.deepEqual(result.trace.find((entry) => entry.operation === 'network').result, {});
});

test('risk overrides preserve explicit zero/false and fall back per field for wrong types', () => {
  const { service, data } = fixture();
  const before = structuredClone(data);
  for (const override of [
    { siem_score: 0, threat_intel_match: false, impossible_travel: false },
    { siem_score: 0 }, { threat_intel_match: false }, { impossible_travel: false },
    { siem_score: '0', threat_intel_match: 0, impossible_travel: 'false' },
  ]) {
    const request = { ...evidence(), risk_evidence: override };
    const result = service.build(request);
    const expected = { ...data.risk };
    for (const [key, value] of Object.entries(override)) {
      if (typeof value === typeof expected[key]) expected[key] = value;
    }
    assert.deepEqual(result.input.risk, expected);
    assert.deepEqual(result.trace.find((entry) => entry.operation === 'risk_evidence').result, override);
  }
  assert.deepEqual(data, before);
});

for (const [method, message] of [
  ['resolveSubject', 'Unable to resolve subject_ref'],
  ['resolveDevice', 'Unable to resolve device_evidence'],
  ['resolveResource', 'Unable to resolve resource_ref'],
  ['resolveRisk', 'Unable to resolve risk context'],
]) {
  for (const failure of ['missing', 'throws']) {
    test(`evidence rejects when ${method} ${failure}`, () => {
      const { service } = fixture({ [method]: () => {
        if (failure === 'throws') throw new Error('synthetic adapter failure');
        return undefined;
      } });
      rejectsBuild(service, evidence(), message);
    });
  }
}

test('evidence trace masks nested sensitive-key values and excludes extra identity/device fields', () => {
  const { service, data } = fixture();
  data.subject.internal = 'private-identity-field';
  data.device.internal = 'private-device-field';
  const request = evidence();
  request.subject_ref = { type: 'mock_token', token: 'synthetic-long-token', session_id: 'short' };
  request.device_evidence.certificate_fingerprint = 'synthetic-fingerprint';
  request.device_evidence.extra = [{ TOKEN: 'another-long-token', session: { id: 'hidden' }, normal: 'visible' }];
  const before = structuredClone(request);
  const result = service.build(request);
  const subjectTrace = result.trace.find((entry) => entry.operation === 'subject_ref');
  assert.deepEqual(subjectTrace.result, { type: 'mock_token', token: 'synt...oken', session_id: '***' });
  const deviceTrace = result.trace.find((entry) => entry.operation === 'device_evidence');
  assert.equal(deviceTrace.result.certificate_fingerprint, 'synt...rint');
  assert.deepEqual(deviceTrace.result.extra, [{ TOKEN: 'anot...oken', session: '<redacted>', normal: 'visible' }]);
  assert.equal(result.trace.find((entry) => entry.source === 'identity').lookupKey, 'mock_token:synt...oken');
  assert.deepEqual(result.trace.find((entry) => entry.source === 'identity').result, canonical().subject);
  assert.deepEqual(result.trace.find((entry) => entry.source === 'device').result, canonical().device);
  const serialized = JSON.stringify(result.trace);
  for (const secret of ['synthetic-long-token', 'synthetic-fingerprint', 'another-long-token', 'private-identity-field', 'private-device-field']) {
    assert.ok(!serialized.includes(secret));
  }
  assert.deepEqual(request, before);
});
