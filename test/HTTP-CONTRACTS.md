# Offline HTTP contracts

Run against the compiled production controllers:

```sh
npm ci
npm run build
node --test test/http-contracts.test.cjs
npm run typecheck
```

The suite starts a real Nest/Fastify application and uses Fastify injection without
opening a listening socket. It checks routing, JSON parsing and serialization,
HTTP errors, asynchronous evaluation, audit query delegation, and the actual
HTML console response. `PdpService` and `AuditLogService` are replaced with
in-memory dependencies. No OPA process, audit file, credentials, or live backend
is accessed. Synthetic response fixtures test transparent controller forwarding,
not validation of the full policy response schema.

These are HTTP boundary tests of the current main branch, not policy-engine,
audit persistence, authorization, readiness, or browser tests. In particular,
health currently reports configuration without probing OPA. The POST currently
returns Nest's default 201 status. Audit limit normalization belongs to the audit
service; this suite tests the controller's number conversion only. Security and
readiness changes proposed in PR #1 may intentionally require updating these
contracts after review.
