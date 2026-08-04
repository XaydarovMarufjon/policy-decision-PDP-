# Loyiha o‘zgarishlari

Bu fayl implementatsiya va arxitektura qarorlarini sanasi bilan qayd etadi.
Yangi o‘zgarishlar eng yuqoriga yoziladi.

## 2026-07-30 — Application integration qo‘llanmasi

- CRM, SIEM, portal va API’larni PEP ortiga joylashtirish uchun alohida
  `docs/INTEGRATION.md` qo‘llanmasi yaratildi.
- Private network va upstream portni public qilmaslik talabi hujjatlashtirildi.
- `APP_UPSTREAM_URL`, `APP_RESOURCE_ID`, OPA resource va role/action sozlash
  bosqichlari misollar bilan yozildi.
- HTTP metodlarini `read/write/delete` actionlariga mapping qilish va upstream
  identity headerlarining trust shartlari qo‘shildi.
- Hozirgi `/app/*` bitta-upstream cheklovi hamda kelajakdagi multi-system route
  registry modeli aniq qayd etildi.
- OPA tayyor policy engine, Rego esa uning policy dasturlash tili ekani
  arxitektura hujjatida tushuntirildi.
- `zta.rego` qaror algoritmi, `zta.json` enterprise konfiguratsiyasi va
  `zta_test.rego` regression testlari o‘rtasidagi mas’uliyatlar yozildi.
- Oddiy yangi resource uchun odatda faqat `zta.json`, maxsus biznes qoidasi
  uchun esa Rego o‘zgarishi kerakligi hujjatlashtirildi.

## 2026-07-30 — MISP runtime integratsiyasi

- PDP `RISK_MODE=misp` bilan qayta ishga tushirildi.
- Lokal MISP endpoint `https://misp-core:443` sifatida PDP’ga ulandi.
- MISP provider’da ilgari ishlatilmagan `MISP_VERIFY_TLS` qo‘llab-quvvatlashi
  dependency-free HTTPS client orqali tuzatildi.
- PDP containeridan real authenticated IOC lookup bajarildi: adapter MISP’dan
  muvaffaqiyatli benign risk javobini oldi.
- Wazuh adapteri tayyor, ammo runtime integratsiyasi uchun zarur tashqi Server
  API/Indexer URL va credentiallar mavjud emas; shu sabab Wazuh hali aktiv emas.
- Arxitektura hujjatiga PEP faqat evidence/identifikator yuborishi, PDP esa
  Keycloak, Wazuh, MISP va OPA orqali contextni tekshirishi va boyitishi haqida
  alohida mas’uliyat modeli qo‘shildi.
- Riskni MISP/Wazuh signallari shakllantirishi, PDP ularni normalizatsiya qilishi
  va yakuniy policy qarorini OPA chiqarishi aniq hujjatlashtirildi.
- Login hozir Keycloak orqali o‘tishi, lekin yakuniy authorization qarorini OPA
  chiqarishi arxitektura hujjatida alohida tushuntirildi.
- Bir nechta himoyalangan tizim uchun Keycloak SSO modeli va Keycloak’ni Entra
  ID, Okta, Auth0 yoki boshqa OIDC provider bilan almashtirish konfiguratsiyasi
  hujjatlashtirildi.
- PEP’ning browser foydalanuvchisini encrypted `pep_sid` cookie, API clientni
  Bearer token orqali tanishi va authorization code → token oqimi
  hujjatlashtirildi.
- PEP tokenni yakuniy ishonch manbasi deb qabul qilmasligi, PDP esa JWT signature,
  issuer, audience, expiry va identity claimlarini JWKS orqali qayta tekshirishi
  qayd etildi.

## 2026-07-29 — Repository cleanup

- macOS tomonidan yaratilgan `.DS_Store` metadata fayli repository ishchi
  katalogidan olib tashlandi.
- Docker build context’dan `.DS_Store`, local environment fayllari, audit
  loglari, coverage va development JWKS keylari chiqarib tashlandi.
- `inputs/`, `requests/`, `mock-sources/`, `dev-keys/` va Compose override’lar
  reference auditidan o‘tkazildi; ular test/integratsiya oqimlarida ishlatilgani
  sabab saqlandi.
- `dist/` generated build artefakti sifatida Git’dan ignore qilinadi, ammo
  lokal `npm run build` va container runtime uchun qayta yaratiladi.
- PDP, OPA, Keycloak, PEP va demo-app development stacki qayta build qilinib
  muvaffaqiyatli ishga tushirildi.
- OPA policy testlari `5/5` natija bilan o‘tdi; PDP live/ready, OPA, PEP va
  Keycloak endpointlari tekshirildi.
- Container buildidagi `npm audit` uchta high-severity dependency ogohlantirishi
  qaytardi. Dependency upgrade alohida compatibility tekshiruvi bilan bajarilishi
  kerak; avtomatik major update qo‘llanmadi.

## 2026-07-29 — Arxitektura hardening

### Reliability

- PEP reverse proxy’dagi TypeScript `Buffer`/`fetch BodyInit` build xatosi
  tuzatildi.
- Identity, device, resource va risk provider lookup’lari parallel qilindi.
- PDP → OPA chaqirig‘iga `OPA_TIMEOUT_MS` qo‘shildi.
- PEP → PDP, PEP → OIDC va PEP → upstream chaqiruvlariga
  `PEP_OUTBOUND_TIMEOUT_MS` qo‘shildi.
- PDP ishlamasa PEP `503` bilan fail-closed javob beradi.

### Configuration safety

- Noma’lum `IDENTITY_MODE`, `DEVICE_MODE`, `RISK_MODE` va `RESOURCE_MODE`
  qiymatlari endi xavfsiz boot failure beradi; mock’ka yashirin fallback yo‘q.
- `docker-compose.prod.yml` production hardening overlay sifatida qo‘shildi.
- Production overlay canonical request va debug response’ni o‘chiradi.
- Production secretlari Compose validation vaqtida majburiy tekshiriladi.
- PDP va OPA’ning direct host portlari production overlay’da yopildi.

### API va observability

- `/pdp/health/live` va dependency-aware `/pdp/health/ready` qo‘shildi.
- Production `/pdp/evaluate` javobi minimal enforcement contractga o‘tkazildi.
- To‘liq canonical input, route va provider trace faqat development
  `?debug=true` rejimida qoldirildi.

### Session security va scaling

- PEP’ning single-process `Map` session store’i olib tashlandi.
- AES-256-GCM encrypted stateless session cookie qo‘shildi.
- Cookie bir xil secret bilan bir nechta replica orasida ishlaydi.
- Login `returnTo` qiymati uchun open-redirect himoyasi qo‘shildi.
- HTTPS redirect URI ishlatilganda cookie `Secure` bo‘ladi va session muddati
  cheklangan.

### Audit

- Synchronous `appendFileSync` asynchronous serialized write queue bilan
  almashtirildi.
- Hajmga asoslangan audit rotation qo‘shildi.
- `PDP_AUDIT_REQUIRED` orqali audit failure’ni request failure qilish mumkin.
- `PDP_AUDIT_HMAC_SECRET` orqali event integrity HMAC qo‘shildi.
- `PDP_AUDIT_WEBHOOK_URL` orqali markaziy SIEM/collector forwarding qo‘shildi.

### Quality gates

- Policy Administrator uchun TTL va deny-escalation unit testlari qo‘shildi.
- GitHub Actions workflow typecheck, build, unit test va OPA policy testlarini
  majburiy qiladi.
- `.env.example` yangi timeout, audit va debug parametrlar bilan yangilandi.

### Verifikatsiya holati

- `npm run typecheck`: o‘tdi.
- `npm run build`: o‘tdi.
- `npm run test:unit`: 2/2 o‘tdi.
- Compose production config validation: o‘tdi.
- Lokal `npm run test:opa`: Docker daemon ishlamagani sabab bajarilmadi; CI’da
  majburiy tekshiruv sifatida saqlangan.
