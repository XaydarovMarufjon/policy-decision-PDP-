const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { InternalServerErrorException } = require('@nestjs/common');
const { MockSourceRepository } = require('../dist/pdp/context/mock-source.repository');

const sources = {
  'identity.json': {
    tokens: { 'fixture-token': 'fixture-user', 'dangling-token': 'missing-user' },
    users: {
      'fixture-user': {
        user: 'fixture-user', role: 'analyst', department: 'SOC', mfa: true,
      },
    },
  },
  'devices.json': {
    devices: {
      'fixture-device': {
        managed: true, edr_status: 'healthy', patch_level: 'ok', ip: '192.0.2.10',
      },
    },
  },
  'risks.json': {
    default: { siem_score: 20, threat_intel_match: true, impossible_travel: true },
    by_source_ip: {
      '192.0.2.10': { siem_score: 0, threat_intel_match: false, impossible_travel: false },
      '192.0.2.20': { siem_score: 90, threat_intel_match: true, impossible_travel: true },
    },
  },
  'resources.json': {
    resources: {
      'fixture-resource': { type: 'database', name: 'fixture-resource', criticality: 'high' },
    },
  },
};

function fixture(t) {
  const directory = mkdtempSync(path.join(tmpdir(), 'pdp-mock-source-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(sources)) {
    writeFileSync(path.join(directory, name), JSON.stringify(content));
  }
  return directory;
}

function repository(directory) {
  const previous = process.env.CONTEXT_SOURCE_DIR;
  process.env.CONTEXT_SOURCE_DIR = directory;
  try {
    return new MockSourceRepository();
  } finally {
    if (previous === undefined) delete process.env.CONTEXT_SOURCE_DIR;
    else process.env.CONTEXT_SOURCE_DIR = previous;
  }
}

const expectedUser = sources['identity.json'].users['fixture-user'];

test('loads user IDs from the configured source directory without a token fallback', (t) => {
  const repo = repository(fixture(t));
  assert.deepEqual(repo.resolveSubject({ type: 'user_id', user_id: 'fixture-user' }), expectedUser);
  assert.equal(repo.resolveSubject({ type: 'user_id', token: 'fixture-token' }), undefined);
});

for (const type of ['mock_token', 'jwt']) {
  test(`resolves ${type} through the mock token map`, (t) => {
    const repo = repository(fixture(t));
    assert.deepEqual(repo.resolveSubject({ type, token: 'fixture-token' }), expectedUser);
    for (const token of [undefined, '', 'unknown-token', 'dangling-token']) {
      assert.equal(repo.resolveSubject({ type, token, user_id: 'fixture-user' }), undefined);
    }
  });
}

test('returns undefined for missing/unknown user IDs and unsupported reference types', (t) => {
  const repo = repository(fixture(t));
  for (const user_id of [undefined, '', 'unknown-user']) {
    assert.equal(repo.resolveSubject({ type: 'user_id', user_id }), undefined);
  }
  assert.equal(repo.resolveSubject({ type: 'unsupported', user_id: 'fixture-user' }), undefined);
});

test('resolves known devices and returns undefined for missing/unknown device IDs', (t) => {
  const repo = repository(fixture(t));
  assert.deepEqual(repo.resolveDevice('fixture-device'), sources['devices.json'].devices['fixture-device']);
  for (const id of [undefined, '', 'unknown-device']) assert.equal(repo.resolveDevice(id), undefined);
});

test('resolves known resources and returns undefined for empty/unknown resource IDs', (t) => {
  const repo = repository(fixture(t));
  assert.deepEqual(repo.resolveResource('fixture-resource'), sources['resources.json'].resources['fixture-resource']);
  for (const id of ['', 'unknown-resource']) assert.equal(repo.resolveResource(id), undefined);
});

test('uses exact source-IP risk overrides, including zero scores and false flags', (t) => {
  const repo = repository(fixture(t));
  for (const ip of ['192.0.2.10', '192.0.2.20']) {
    assert.deepEqual(repo.resolveRisk(ip), sources['risks.json'].by_source_ip[ip]);
  }
});

test('uses default risk for missing, empty and unknown source IPs', (t) => {
  const repo = repository(fixture(t));
  for (const ip of [undefined, '', '192.0.2.99']) {
    assert.deepEqual(repo.resolveRisk(ip), sources['risks.json'].default);
  }
});

test('keeps the construction-time snapshot while new instances reload source files', (t) => {
  const directory = fixture(t);
  const first = repository(directory);
  const changed = { ...sources['identity.json'], users: { 'fixture-user': { ...expectedUser, role: 'auditor' } } };
  writeFileSync(path.join(directory, 'identity.json'), JSON.stringify(changed));
  assert.deepEqual(first.resolveSubject({ type: 'user_id', user_id: 'fixture-user' }), expectedUser);
  assert.deepEqual(repository(directory).resolveSubject({ type: 'user_id', user_id: 'fixture-user' }), changed.users['fixture-user']);
});

test('defaults to mock-sources under the working directory when the override is absent', (t) => {
  const directory = fixture(t);
  const cwd = path.join(directory, 'working-directory');
  const sourceDirectory = path.join(cwd, 'mock-sources');
  mkdirSync(sourceDirectory, { recursive: true });
  for (const [name, content] of Object.entries(sources)) {
    writeFileSync(path.join(sourceDirectory, name), JSON.stringify(content));
  }
  const env = { ...process.env };
  delete env.CONTEXT_SOURCE_DIR;
  const modulePath = require.resolve('../dist/pdp/context/mock-source.repository');
  const script = `const { MockSourceRepository } = require(${JSON.stringify(modulePath)});\n` +
    `process.stdout.write(JSON.stringify(new MockSourceRepository().resolveSubject({ type: 'user_id', user_id: 'fixture-user' })));`;
  const result = spawnSync(process.execPath, ['-e', script], { cwd, env, encoding: 'utf8' });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), expectedUser);
});

for (const filename of Object.keys(sources)) {
  for (const failure of ['missing', 'invalid JSON']) {
    test(`fails construction with a source-specific 500 error for ${failure} in ${filename}`, (t) => {
      const directory = fixture(t);
      const file = path.join(directory, filename);
      if (failure === 'missing') rmSync(file);
      else writeFileSync(file, '{ invalid JSON');
      assert.throws(() => repository(directory), (error) => {
        assert.ok(error instanceof InternalServerErrorException);
        assert.equal(error.getStatus(), 500);
        assert.ok(error.message.startsWith(`Failed to load context source ${filename}: `));
        return true;
      });
    });
  }
}
