# Context builder contract tests

Run against the current `main` implementation from the repository root:

```sh
npm ci
npm run typecheck
npm run build
node --test test/context-builder.service.test.cjs
```

Build immediately before testing: the suite imports the compiled service from
`dist/`. No new dependencies, environment changes or external services are needed.

Fresh synthetic source doubles exercise the public `build` method: canonical
shape/type validation and declared-field projection (strings are not trimmed),
evidence lookup arguments and context assembly, optional request IDs/network,
zero/false and partial risk overrides, missing/throwing sources, and request trace
masking. Timing assertions check nonnegative integer durations, not wall-clock
thresholds. Request and source fixtures are checked for unintended mutation.

These tests are separate from PR #2's mock repository/file-loading tests. They do
not verify JWTs, HTTP authorization, OPA policy decisions, audit persistence, or
production security. Evidence risk overrides are the existing mock prototype
behavior, not a recommendation for untrusted production callers.

The suite targets the synchronous mock-source constructor on `main`. Draft PR #1
changes that interface to asynchronous providers and gates canonical input; these
tests will need deliberate adaptation if that architecture lands. This change
does not modify or validate that draft. Run OPA tests separately with
`npm run test:opa` when Docker is available.
