# OPA adapter contract tests

From the repository root, with dependencies installed:

```sh
npm run build
node --test test/opa-policy-engine.service.test.cjs
```

The 18 tests load the compiled production adapter and use Node's built-in test runner. Each test replaces `fetch` with an isolated stub; no OPA server, network, Docker, database or credentials are used. Environment changes are restored immediately after constructing the adapter, and Node restores each fetch mock after its test. Do not enable concurrent execution within this test file because `fetch` and environment configuration are process-wide.

Covered contracts:

- Canonical request envelope, JSON headers, POST method, default/configured URL and input preservation.
- Complete allow/deny mapping, OPA decision IDs, nullish fallback fields and meaningful zero/empty values.
- HTTP rejection before body parsing, Error/non-Error transport failures, and no implicit retries.
- Missing decision responses and reverse-order completion of simultaneous requests with independent fallback risk scores.

These tests preserve the current adapter contract; they do not validate OPA policy decisions or make the adapter production-ready. In particular, the current adapter has no request timeout and does not validate all decoded response fields at runtime. Malformed JSON, non-object JSON and unsupported truthy decision values are not covered by a validated-response contract. Do not treat this suite as proof of fail-closed behavior for arbitrary upstream payloads. Transport hardening is a separate concern from these tests.

Run `npm run typecheck` for production TypeScript and `npm run test:opa` for the separate Rego policy tests when Docker is available. The latter is not exercised by the mocked adapter suite.
