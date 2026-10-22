const assert = require('node:assert/strict');
const { test, before, after, beforeEach } = require('node:test');
require('reflect-metadata');
const { Module, BadRequestException, ServiceUnavailableException } = require('@nestjs/common');
const { NestFactory } = require('@nestjs/core');
const { FastifyAdapter } = require('@nestjs/platform-fastify');
const { PdpController } = require('../dist/pdp/pdp.controller');
const { PdpService } = require('../dist/pdp/pdp.service');
const { AuditLogService } = require('../dist/pdp/audit/audit-log.service');
const { AppController } = require('../dist/app.controller');
const { adminConsoleHtml } = require('../dist/ui/admin-console');

let app, server, evaluations, limits, evaluate;
const result = { decisionId: 'synthetic-id', decision: 'deny', reason: ['synthetic reason'], pa: { enforcementCommand: 'block', ttlSeconds: 0 } };
const audit = { path: '/synthetic/audit.jsonl', count: 1, entries: [{ decisionId: 'synthetic-id' }] };
const pdp = { opaDecisionUrl: 'http://synthetic.invalid/decision', evaluate: (body) => { evaluations.push(body); return evaluate(body); } };
class HttpContractModule {}
Module({ controllers: [PdpController, AppController], providers: [
  { provide: PdpService, useValue: pdp },
  { provide: AuditLogService, useValue: { listRecent: (limit) => { limits.push(limit); return audit; } } },
]})(HttpContractModule);
before(async () => {
  app = await NestFactory.create(HttpContractModule, new FastifyAdapter(), { logger: false });
  await app.init();
  server = app.getHttpAdapter().getInstance();
  await server.ready();
});
after(async () => { if (app) await app.close(); });
beforeEach(() => { evaluations = []; limits = []; evaluate = async () => result; });

test('root serves the actual console as HTML', async () => {
  const response = await server.inject({ method: 'GET', url: '/' });
  assert.equal(response.statusCode, 200);
  assert.match(response.headers['content-type'], /^text\/html; charset=utf-8$/);
  assert.equal(response.body, adminConsoleHtml);
});
test('health returns configured adapter URL without evaluating or reading audit', async () => {
  const response = await server.inject({ method: 'GET', url: '/pdp/health' });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.json(), { status: 'ok', service: 'pdp', opaDecisionUrl: pdp.opaDecisionUrl });
  assert.deepEqual(evaluations, []); assert.deepEqual(limits, []);
});
test('evaluate forwards nested JSON unchanged and serializes service result', async () => {
  const payload = { requestId: 'synthetic', evidence: { values: [false, 0, 'ü'] } };
  const response = await server.inject({ method: 'POST', url: '/pdp/evaluate', payload });
  assert.equal(response.statusCode, 201);
  assert.match(response.headers['content-type'], /^application\/json/);
  assert.deepEqual(evaluations, [payload]); assert.deepEqual(response.json(), result);
});
test('evaluate awaits asynchronous result before HTTP completion', async () => {
  let release, entered;
  const started = new Promise(resolve => { entered = resolve; });
  evaluate = () => { entered(); return new Promise(resolve => { release = resolve; }); };
  let completed = false;
  const pending = server.inject({ method: 'POST', url: '/pdp/evaluate', payload: {} }).then(r => { completed = true; return r; });
  await started; assert.equal(completed, false); release(result);
  assert.deepEqual((await pending).json(), result);
});
for (const [label, error, status] of [
  ['validation', new BadRequestException('synthetic invalid input'), 400],
  ['upstream unavailable', new ServiceUnavailableException('synthetic unavailable'), 503],
]) test(`evaluate preserves ${label} HTTP errors`, async () => {
  evaluate = async () => { throw error; };
  const response = await server.inject({ method: 'POST', url: '/pdp/evaluate', payload: {} });
  assert.equal(response.statusCode, status); assert.equal(response.json().message, error.message);
  assert.equal(evaluations.length, 1);
});
test('unexpected service errors use generic 500 response, not internal text', async () => {
  evaluate = async () => { throw new Error('synthetic internal detail'); };
  const response = await server.inject({ method: 'POST', url: '/pdp/evaluate', payload: {} });
  assert.equal(response.statusCode, 500);
  assert.equal(response.json().message, 'Internal server error');
  assert.equal(response.body.includes('synthetic internal detail'), false);
});
test('malformed JSON is rejected before invoking PDP', async () => {
  const response = await server.inject({ method: 'POST', url: '/pdp/evaluate', headers: { 'content-type': 'application/json' }, payload: '{broken' });
  assert.equal(response.statusCode, 400); assert.deepEqual(evaluations, []);
});
for (const [query, expected] of [['', 20], ['?limit=', 20], ['?limit=7', 7], ['?limit=0', 0], ['?limit=2.5', 2.5]]) {
  test(`audit query ${query || '(absent)'} delegates numeric limit and returns envelope`, async () => {
    const response = await server.inject({ method: 'GET', url: '/pdp/audit' + query });
    assert.equal(response.statusCode, 200); assert.deepEqual(limits, [expected]);
    assert.deepEqual(response.json(), audit);
  });
}
test('unknown path and wrong evaluation method return 404 without service calls', async () => {
  for (const url of ['/not-a-route', '/pdp/evaluate']) {
    assert.equal((await server.inject({ method: 'GET', url })).statusCode, 404);
  }
  assert.deepEqual(evaluations, []); assert.deepEqual(limits, []);
});
