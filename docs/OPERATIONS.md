# Ishga tushirish va operatsiya qo‘llanmasi

## Lokal development

```bash
docker compose up -d --build
```

Base compose development uchun mock providerlar, canonical test inputi va dev
default secretlarni yoqadi. Uni production konfiguratsiyasi sifatida ishlatmang.

## Production overlay

Kerakli secretlarni secret manager orqali bering:

```bash
export PDP_SHARED_SECRET='long-random-service-secret'
export OIDC_CLIENT_SECRET='oidc-client-secret'
export COOKIE_SECRET='long-random-cookie-encryption-secret'
export PDP_AUDIT_HMAC_SECRET='independent-audit-signing-secret'

docker compose \
  -f docker-compose.yml \
  -f docker-compose.keycloak.yml \
  -f docker-compose.pep.yml \
  -f docker-compose.prod.yml \
  up -d --build
```

Production overlay canonical input va debug response’ni o‘chiradi, secretlarni
majburiy qiladi, PDP/OPA host portlarini olib tashlaydi va readiness checklarni
yoqadi.

## Muhim konfiguratsiya

| Variable | Default | Vazifasi |
| --- | --- | --- |
| `OPA_TIMEOUT_MS` | `2000` | PDP → OPA timeout |
| `PEP_OUTBOUND_TIMEOUT_MS` | `4000` | PEP tashqi chaqiruvlari timeout’i |
| `ALLOW_CANONICAL_INPUT` | `false` kod default | Ishonchli canonical test path |
| `PDP_DEBUG_RESPONSE` | `false` | Development trace so‘rovi |
| `PDP_AUDIT_MAX_BYTES` | `10485760` | Audit rotation chegarasi |
| `PDP_AUDIT_REQUIRED` | `false` | Audit yozilmasa requestni yiqitish |
| `PDP_AUDIT_HMAC_SECRET` | unset | Audit integrity HMAC secret |
| `PDP_AUDIT_WEBHOOK_URL` | unset | Markaziy SIEM endpoint |
| `PDP_AUDIT_WEBHOOK_TIMEOUT_MS` | `2000` | SIEM forwarding timeout |

To‘liq konfiguratsiya va provider mode’lari `.env.example` ichida berilgan.

## Health va diagnostika

```bash
curl http://localhost:3000/pdp/health/live
curl http://localhost:3000/pdp/health/ready
curl http://localhost:8000/health
```

Readiness `503` qaytarsa birinchi navbatda OPA container holati va
`OPA_DECISION_URL`ni tekshiring.

Development’da batafsil qaror oqimi:

```bash
curl -X POST 'http://localhost:3000/pdp/evaluate?debug=true' \
  -H 'Content-Type: application/json' \
  -H "X-PDP-Auth: ${PDP_SHARED_SECRET}" \
  --data-binary @requests/pdp/allow-evidence.json
```

`debug=true` production’da e’tiborga olinmaydi.

## MISP va Wazuh integratsiyasi

Lokal MISP bilan ishga tushirish:

```bash
docker compose -f docker-compose.yml -f docker-compose.keycloak.yml \
  -f docker-compose.pep.yml -f docker-compose.app.yml \
  -f docker-compose.misp.yml up -d --build
```

Wazuh mavjud tashqi Server API va Indexer’ga ulanadi. Quyidagi qiymatlar real
Wazuh administratoridan olinishi kerak:

```bash
export WAZUH_API_URL='https://host.docker.internal:55000'
export WAZUH_API_USER='...'
export WAZUH_API_PASSWORD='...'
export WAZUH_INDEXER_URL='https://host.docker.internal:9200'
export WAZUH_INDEXER_USER='...'
export WAZUH_INDEXER_PASSWORD='...'
```

Keyin `docker-compose.wazuh.yml` overlay qo‘shiladi. Bu `DEVICE_MODE=wazuh` va
`RISK_MODE=wazuh-misp`ni yoqadi. Credentiallardan biri yo‘q bo‘lsa PDP ataylab
boot qilmaydi — mock yoki yolg‘on integratsiyaga fallback qilinmaydi.

## Verifikatsiya

```bash
npm run typecheck
npm run build
npm run test:unit
npm run test:opa
```

GitHub Actions bu to‘rtta tekshiruvni push va pull requestlarda bajaradi. OPA
testi Docker daemon talab qiladi.

## Audit operatsiyasi

Default path: `/app/audit-logs/pdp-decisions.jsonl`. Rotation eski faylga UTC
timestamp suffix qo‘shadi. Production’da volume retention va rotated fayllarni
arxivlash siyosati infrastructure darajasida belgilanadi.

SIEM webhook yoqilganda endpoint har audit eventini `application/json` POST
sifatida qabul qilishi kerak. `PDP_AUDIT_REQUIRED=true` bo‘lsa lokal yozish yoki
webhook forwarding xatosi PDP requestini muvaffaqiyatsiz qiladi.

## Secret rotation

- `PDP_SHARED_SECRET`: PEP va PDP’da bir vaqtda almashtiriladi.
- `COOKIE_SECRET`: almashtirilganda mavjud browser sessionlari bekor bo‘ladi.
- `PDP_AUDIT_HMAC_SECRET`: audit verifier’da versiya/key-id bilan boshqarilishi
  tavsiya etiladi; hozirgi event contract key-id saqlamaydi.
- Secret qiymatlarini repository yoki Compose fayliga yozmang.

## Known limitations

- 2026-07-29 build holatida `npm audit` uchta high-severity dependency
  ogohlantirishini ko‘rsatadi. Upgrade’dan oldin NestJS/Fastify compatibility
  va authorization regression testlari bajarilishi kerak.
- PDP service authentication hozir shared secretga asoslangan; mTLS hali yo‘q.
- Rotated audit fayllarini avtomatik upload/delete qilish infrastructure
  zimmasida.
- Stateless session cookie access token hajmiga bog‘liq; juda katta tokenlarda
  Redis-backed session adapteri kerak bo‘lishi mumkin.
