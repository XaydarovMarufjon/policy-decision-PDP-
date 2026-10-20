# PDP orchestration regression tests

From the repository root:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
node --test test/pdp.service.test.cjs
```

Build immediately before testing: the suite imports compiled `dist/` code.
It uses Node's built-in runner and fresh synthetic collaborator doubles. No
HTTP server, OPA, filesystem audit sink, external data, network request, real
identity, or additional package is used.

The suite protects the orchestration contract, separately from context-source,
context-builder, audit-persistence and policy-administrator tests: exact
collaborator inputs/order, waiting for the engine, allow/deny response projection,
route/response consistency, optional identifiers, canonical/evidence context,
unchanged error propagation, no downstream calls after failures, and concurrent
requests that resolve out of order. The engine score deliberately differs from
the input score to detect accidental substitution. Deferred promises control
ordering without sleep timers; identifier/timestamp format checks avoid fixed
wall-clock expectations.

These tests do not validate policy correctness, TTL selection, OPA transport,
authentication, HTTP error mapping, request sanitization, audit durability or
production security. The audit-failure case uses an injected throwing double;
the real audit service currently catches its ordinary append errors. No audit
failure policy is changed or recommended here.

This suite targets current main's synchronous context-builder and audit-call
contracts. Draft #1 changes context building to asynchronous providers and
introduces additional enforcement/readiness behavior. Adapt the test doubles
and assertions deliberately if that architecture lands; these tests do not
validate that draft or require preservation of its predecessor architecture.
Run the separate OPA tests with `npm run test:opa` where Docker is available.
