# Mock context source tests

From the repository root, install the locked dependencies, build the current
TypeScript sources, and run the tests with Node's built-in test runner:

```sh
npm ci
npm run typecheck
npm run build
node --test test/mock-source.repository.test.cjs
```

Build immediately before running the test file: it imports the compiled
`MockSourceRepository` from `dist/`, so a stale build would test stale code.
No additional test dependencies are needed.

The suite uses temporary synthetic JSON fixtures. It covers the configured and
default source directories, user ID and mock-token lookups, device/resource
misses, risk overrides and fallback, construction-time snapshots, and startup
failures for each missing or malformed JSON source. Temporary files are removed
after each test and the source-directory environment variable is restored after
each construction. The default-directory case runs in an isolated subprocess.

The `jwt` reference type in this mock repository uses the same local token map
as `mock_token`; this suite does not claim to verify JWT signatures or real
identity providers. It does not contact OPA, start a server, write audit logs,
read the checked-in mock data, or test policy decisions. Existing OPA checks
remain available separately through `npm run test:opa` with Docker installed.
