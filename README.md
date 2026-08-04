# Policy Engine PDP

## Documentation

- [Tizim arxitekturasi](docs/ARCHITECTURE.md)
- [Boshqa tizimlarni integratsiya qilish](docs/INTEGRATION.md)
- [Ishga tushirish va operatsiya](docs/OPERATIONS.md)
- [O‘zgarishlar tarixi](docs/CHANGELOG.md)

Har bir arxitektura, konfiguratsiya yoki operatsion o‘zgarish tegishli hujjat va
`docs/CHANGELOG.md` bilan birga yangilanishi kerak.

This stage contains a PDP wrapper around OPA:

```text
Manual request -> PDP Context Builder -> OPA / PE -> PA -> PDP response
```

Each decision signal comes from a **pluggable provider**, selected by env so mocks
can be swapped for real systems one at a time (see the target architecture in the
plan). Current sources:

| Signal | Env | `mock` (default JSON) | Real |
| --- | --- | --- | --- |
| identity | `IDENTITY_MODE` | `mock-sources/identity.json` | `oidc` (JWKS-verified JWT) |
| risk | `RISK_MODE` | `mock-sources/risks.json` | `misp`, `wazuh`, `wazuh-misp` (composite) |
| device | `DEVICE_MODE` | `mock-sources/devices.json` | `wazuh` (live EDR posture) |
| resource | `RESOURCE_MODE` | `mock-sources/resources.json` | `opa-data` **(default)** |

`RESOURCE_MODE=opa-data` (the default) reads the resource inventory straight from
`opa/data/zta.json`, so OPA is the single source of truth for resources — no
duplicated `resources.json` to drift. The PEP sends the **real client IP**
(`PEP_TRUST_PROXY` controls proxy trust), not a hardcoded value.

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

The base compose file is a local-development stack. For a hardened deployment,
use the production overlay and provide secrets through your secret manager:

```bash
docker compose -f docker-compose.yml -f docker-compose.pep.yml \
  -f docker-compose.prod.yml up -d --build
```

The production overlay disables canonical input and debug responses, removes
direct PDP/OPA host ports, requires secrets, enables readiness checks, and makes
audit persistence mandatory.

Health checks:

```bash
curl http://localhost:8181/health
curl http://localhost:3000/pdp/health
```

Open the PDP test console:

```text
http://localhost:3000/
```

## Identity: Mock vs Real User (OIDC)

The subject (user) can be resolved from two sources, selected by `IDENTITY_MODE`:

- `mock` (default) — resolves the user from `mock-sources/identity.json`.
- `oidc` — verifies a **real JWT** against an Identity Provider's JWKS and maps
  its claims (`user`, `role`, `department`, `mfa`) into the canonical subject.
  Only the identity source changes; device, risk, and resource stay on mock
  adapters.

### Test as a real user now (offline, no IdP)

A local test-token generator stands in for a real IdP. It writes a JWKS to
`dev-keys/jwks.json` and prints a signed JWT:

```bash
npm run gen:token -- --user ali.valiyev --role analyst --department SOC --mfa true
```

Start the stack in real-user mode and send the printed token as
`subject_ref.token` with `"type": "jwt"`:

```bash
docker compose -f docker-compose.yml -f docker-compose.oidc.yml up -d
```

`requests/pdp/allow-real-user.json` is a ready template — replace
`REPLACE_WITH_REAL_JWT` with the generated token, then:

```bash
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  --data-binary @requests/pdp/allow-real-user.json
```

Tampered signatures, `alg:none` forgeries, wrong issuer, and expired tokens are
rejected with HTTP 400.

### Test with a real Keycloak IdP

A bundled Keycloak container issues real user tokens. It imports the `soc`
realm (`keycloak/realm-soc.json`) with roles and seeded users on first start:

```bash
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml up -d
```

| User | Password | Role | Department | MFA |
| --- | --- | --- | --- | --- |
| `ali.valiyev` | `Passw0rd!` | analyst | SOC | true |
| `malika.saidova` | `Passw0rd!` | auditor | GRC | true |
| `vali.karimov` | `Passw0rd!` | guest | HR | false |

Admin console: `http://localhost:8080` (`admin` / `admin`).

Get a real access token (Resource Owner Password grant on the `pdp-test`
public client) and evaluate it through the PDP:

```bash
TOKEN=$(./scripts/kc-token.sh ali.valiyev)
curl -s -X POST http://localhost:3000/pdp/evaluate \
  -H "Content-Type: application/json" \
  -d "$(jq --arg t "$TOKEN" '.subject_ref.token=$t' requests/pdp/allow-real-user.json)"
```

The PDP verifies the token against Keycloak's JWKS (`http://keycloak:8080/...`)
and maps `preferred_username`, `realm_access.roles`, `department`, and the `mfa`
claim into the canonical subject. The issuer is pinned to
`http://localhost:8080/realms/soc` (via `KC_HOSTNAME`) so tokens verify the same
whether fetched from the host or from inside the compose network.

### Create a user

For a meaningful PDP decision a user needs a **realm role** plus the
**`department`** and **`mfa`** attributes. Three ways:

1. **Helper script** (Admin API, one call):

   ```bash
   ./scripts/kc-create-user.sh nodira.tosheva analyst SOC true
   ./scripts/kc-token.sh nodira.tosheva            # -> real token, PDP allow
   ```

2. **Admin console** — `http://localhost:8080` → realm `soc` → Users → Add user.
   The `Department` and `MFA` fields appear under user metadata (declared as
   managed attributes in the realm). Set a password under Credentials and assign
   a role under Role mapping.

3. **Realm seed** — add the user to `keycloak/realm-soc.json` (version
   controlled; applied on a fresh volume import).

Users created via the UI/API **persist** in the `keycloak-data` volume across
container recreation. Note: `--import-realm` only runs on an empty volume, so
after the first seed, edits to `realm-soc.json` are not re-imported — wipe the
volume (`docker volume rm policy-decision-pdp-_keycloak-data`) or import
manually to re-apply.

> Keycloak 26 note: custom attributes are governed by the declarative user
> profile. The realm enables them (`department`/`mfa` declared + unmanaged
> attributes ON); without that, attributes set via the API/UI are silently
> dropped from tokens. Always create a user with all required fields in one call
> — a partial `PUT` replaces the whole representation and yields "Account is not
> fully set up".

### Point at your own IdP (Entra / Okta / existing Keycloak)

No code change — set env and point at the IdP's JWKS (see `.env.example`):

```bash
IDENTITY_MODE=oidc
OIDC_ISSUER=https://idp.example.com/realms/soc
OIDC_JWKS_URL=https://idp.example.com/realms/soc/protocol/openid-connect/certs
OIDC_ROLE_PRIORITY=admin,analyst,auditor,guest
```

Claim mapping defaults are Keycloak-style (`preferred_username`,
`realm_access.roles`, `department`, `amr`) and are each overridable via
`OIDC_CLAIM_*` env vars.

Back to mock mode: `docker compose up -d` (without an override).

## Full Zero Trust flow: PEP gateway with browser login

The PEP (Policy Enforcement Point) closes the loop: a user logs in through
Keycloak in the browser (OIDC authorization-code + PKCE), then the PEP asks the
PDP to authorize every resource/action before serving it.

```text
Browser --login--> Keycloak --token--> PEP session
Browser --request--> PEP --evidence(+token)--> PDP --allow/deny--> permit/serve | block/403
```

Start the full stack (base + Keycloak + PEP):

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.keycloak.yml \
  -f docker-compose.pep.yml up -d --build
```

Open the gateway and log in as `ali.valiyev` / `Passw0rd!`:

```text
http://localhost:8000/
```

The protected page shows the PDP decision for the selected `resource:action`.
Use the buttons to try combinations — e.g. `incident_db:read` is permitted for
an analyst, `incident_db:write` is denied (403), `case_management:write` is
permitted. `Logout` ends the session via Keycloak.

The PEP also accepts API calls with a bearer token (returns JSON, HTTP 200/403):

```bash
TOKEN=$(./scripts/kc-token.sh ali.valiyev)
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/?resource=incident_db&action=write"   # -> 403
```

Ports: PEP `8000`, PDP `3000`, OPA `8181`, Keycloak `8080`.

## Protecting a real app: PEP reverse proxy (`/app/*`)

The PEP can front an ordinary web-app that knows nothing about Zero Trust.
`docker-compose.app.yml` adds `demo-app` (a small notes app on internal port
5000, **no published ports** — reachable only through the PEP), and the PEP
proxies `/app/*` to it after a PDP `allow`:

```text
Browser --/app/*--> PEP --evidence--> PDP --allow--> proxy to demo-app:5000
                                          --deny---> 403 (request never reaches the app)
```

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.keycloak.yml \
  -f docker-compose.pep.yml \
  -f docker-compose.app.yml up -d --build
```

Open `http://localhost:8000/app/` and log in as `ali.valiyev` / `Passw0rd!`.
The HTTP method maps to the ZTA action: `GET -> read`, `POST/PUT/PATCH ->
write`, `DELETE -> delete`. The analyst role has `my_app: [read, write]`, so
viewing and adding notes works, but the Delete button returns 403 from the PDP.
The app receives the verified identity as `X-User` / `X-Role` headers (never
the raw token). To protect your own app instead, point `APP_UPSTREAM_URL` at it
and register its resource id (`APP_RESOURCE_ID`) with role grants in
`opa/data/zta.json`.

## Version checks

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
