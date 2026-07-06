# Policy Engine PDP

This stage contains a PDP wrapper around OPA:

```text
Manual request -> PDP Context Builder -> OPA / PE -> PA -> PDP response
```

It does not include a real PEP, database, identity source, SIEM, or device source integration yet. Those external systems are simulated with local JSON files under `mock-sources/`.

OPA is pinned to `openpolicyagent/opa:1.18.2` for production-style repeatability. Do not use `latest` for production.

## Layout

```text
src/
  pdp/
    context/
    policy-engine/
    policy-administrator/
mock-sources/
  identity.json
  devices.json
  risks.json
  resources.json
requests/
  pdp/
    allow-evidence.json
    deny-high-risk-evidence.json
    deny-unknown-role-evidence.json
    allow-canonical.json
opa/
  config/opa-config.yaml
  data/zta.json
  policies/zta.rego
  policies/zta_test.rego
inputs/
  allow.json
  deny-*.json
```

`zta.rego` contains evaluation logic. `zta.json` contains enterprise policy data: roles, resources, risk thresholds, and device requirements.

## Start Stack

```bash
docker compose up -d --build
```

Health checks:

```bash
curl http://localhost:8181/health
curl http://localhost:3000/pdp/health
```

Open the PDP test console:

```text
http://localhost:3000/
```

Check the pinned version:

```bash
docker run --rm openpolicyagent/opa:1.18.2 version
```

Check the running container version:

```bash
docker exec zta-pe-opa /opa version
```

## Test PDP

Allow through Context Builder evidence flow:

```bash
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  --data-binary @requests/pdp/allow-evidence.json
```

High risk deny through Context Builder evidence flow:

```bash
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  --data-binary @requests/pdp/deny-high-risk-evidence.json
```

Unknown role deny through Context Builder evidence flow:

```bash
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  --data-binary @requests/pdp/deny-unknown-role-evidence.json
```

Canonical JSON passthrough flow:

```bash
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  --data-binary @requests/pdp/allow-canonical.json
```

PDP response shape:

```text
decisionId
requestId
decision
reason
route
context.canonicalInput
context.trace
pe.matchedPolicyId
pa.enforcementCommand
pa.ttlSeconds
pa.obligations
```

`route` shows the full decision path: request received, Context Builder processing, PE/OPA evaluation, PA enforcement mapping, and final PDP response.

`context.trace` shows which source adapter was used, lookup key, status, duration, and sanitized source result.

## PDP Audit Logs

Every PDP decision is written as sanitized JSONL:

```text
/app/audit-logs/pdp-decisions.jsonl
```

The Docker Compose service stores that path in the `pdp-audit-logs` volume.

View logs:

```bash
docker exec zta-pdp tail -n 20 /app/audit-logs/pdp-decisions.jsonl
```

Read logs through PDP API:

```bash
curl http://localhost:3000/pdp/audit?limit=20
```

The admin UI also has a separate `PDP Audit Logs` panel:

```text
http://localhost:3000/
```

Each event includes `decisionId`, `requestId`, subject, resource, action, decision, matched policy, risk score, enforcement command, context sources, and source trace. Raw tokens are not written.

## Test Policies

```bash
docker run --rm \
  -v "/home/marufjon/projects/Policy Engine/opa:/work:ro" \
  openpolicyagent/opa:1.18.2 test /work/policies /work/data
```

## Evaluate Inputs

These commands call OPA directly and bypass PDP, Context Builder, and PA. Use them only to test the PE layer.

OPA endpoint mapping:

```text
package sentryx.zta + decision rule
=> /v1/data/sentryx/zta/decision
```

Allow case:

```bash
curl -s -X POST http://localhost:8181/v1/data/sentryx/zta/decision \
  -H "Content-Type: application/json" \
  --data-binary @inputs/allow.json
```

High risk deny:

```bash
curl -s -X POST http://localhost:8181/v1/data/sentryx/zta/decision \
  -H "Content-Type: application/json" \
  --data-binary @inputs/deny-high-risk.json
```

Access requirements deny:

```bash
curl -s -X POST http://localhost:8181/v1/data/sentryx/zta/decision \
  -H "Content-Type: application/json" \
  --data-binary @inputs/deny-default.json
```

Threat intelligence deny:

```bash
curl -s -X POST http://localhost:8181/v1/data/sentryx/zta/decision \
  -H "Content-Type: application/json" \
  --data-binary @inputs/deny-threat-intel.json
```

Impossible travel deny:

```bash
curl -s -X POST http://localhost:8181/v1/data/sentryx/zta/decision \
  -H "Content-Type: application/json" \
  --data-binary @inputs/deny-impossible-travel.json
```
