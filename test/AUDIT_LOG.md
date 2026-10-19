# Audit log service regression tests

From the repository root, using a Node.js version supported by the dependencies:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run typecheck
npm run build
node --test test/audit-log.service.test.cjs
```

The tests use Node's built-in runner against compiled application code. Rebuild
before running after any source changes. No HTTP server, OPA, Docker, real user
data, or external services are involved. Each test owns a temporary directory
and removes it after completion. The audit path environment variable is restored
immediately after service construction, and logger capture is instance-local.

Coverage includes exact JSON projection and optional identifiers, UTF-8 JSONL
persistence, append order (not timestamp sorting), read limits and total line
counts, whitespace/CRLF/final-line handling, malformed records within and outside
the selected window, and deterministic directory/append failures with recovery.

## Scope and compatibility

These tests characterize current main's synchronous `AuditLogService`. They do
not duplicate the mock-source repository or context-builder suites in drafts #2
and #3. Draft #1 changes this component to asynchronous queued writes, adds route
fields, and changes counting to a bounded tail window, among other changes. If
that architecture lands, deliberately adapt these assertions and await writes;
this suite is not a validation of that draft or a requirement to preserve the
old architecture.

`count` currently means all nonblank lines, including malformed JSON. `limit`
selects a trailing line window before malformed entries are skipped, so fewer
valid entries may be returned without backfilling. The tests document these
existing semantics, not a recommendation for a future API. Only ordinary finite
numeric limits are covered.

The exact projection assertion checks which response fields are persisted. The
service passes through context sources, trace, and warnings; it does not itself
recursively sanitize those values. These tests use a synthetic, already-redacted
trace and make no security/redaction guarantee. They do not verify HTTP access
control, OPA policy decisions, audit integrity, concurrent writers, rotation,
webhooks, crash durability, or production deployment behavior. Read/serialization
failure behavior is outside this suite's scope.
