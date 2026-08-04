# Tizim arxitekturasi

Ushbu hujjat SentryX Policy Decision Point loyihasining komponentlari, ishonch
chegaralari va qaror oqimini tushuntiradi. Kod yoki deployment modeli
o‘zgarganda bu hujjat ham yangilanishi kerak.

## Maqsad

Tizim Zero Trust access so‘rovini tashqi signallar bilan boyitadi, OPA orqali
policy qarorini chiqaradi va PEP bajarishi mumkin bo‘lgan ko‘rsatmaga
aylantiradi. Himoyalanayotgan ilova authorization mantiqini o‘zida saqlamaydi.

## Komponentlar

```text
Browser/API
    |
    v
PEP gateway --------> Keycloak / OIDC
    |
    | evidence + verified-user token
    v
PDP API
    |
    v
Context Builder
    |-- IdentityProvider: mock | OIDC/JWKS
    |-- DeviceProvider:   mock | Wazuh
    |-- RiskProvider:     mock | MISP | Wazuh | composite
    `-- ResourceProvider: mock | OPA data
    |
    | canonical input
    v
OPA Policy Engine
    |
    | allow/deny + policy metadata
    v
Policy Administrator
    |
    | permit/block + TTL + obligations
    v
PEP enforcement ------> protected upstream application
    |
    `------------------> audit JSONL / optional SIEM webhook
```

### PEP — Policy Enforcement Point

`src/pep/main.ts` browser OIDC loginini, API bearer tokenlarini va `/app/*`
reverse-proxy oqimini boshqaradi. Har bir himoyalangan request uchun PDP’dan
yangi qaror olinadi. Faqat aniq `allow` javobi upstream’ga uzatiladi; timeout,
transport xatosi yoki noto‘g‘ri javob fail-closed natija beradi.

Brauzer sessiyasi AES-256-GCM bilan shifrlangan va autentifikatsiyalangan
stateless cookie’da saqlanadi. Shu sabab bir xil `COOKIE_SECRET` ishlatadigan
bir nechta PEP replica sticky session yoki lokal `Map`ga muhtoj emas.

### PDP — Policy Decision Point

NestJS PDP `/pdp/evaluate` endpointini beradi. `PdpService` faqat orchestration
qiladi:

1. Context Builder requestni canonical inputga aylantiradi.
2. OPA adapter policy qarorini oladi.
3. Policy Administrator enforcement command, TTL va obligationlarni yaratadi.
4. Qaror auditga yoziladi.
5. PEP’ga minimal enforcement contract qaytariladi.

Production response ichki adapter nomlari, canonical input yoki route trace’ni
oshkor qilmaydi. `?debug=true` faqat `ALLOW_DEV_DEFAULTS=true` bo‘lgan development
muhitida to‘liq diagnostik javob beradi.

### Context Builder va providerlar

Identity, device, resource va risk lookup’lari o‘zaro mustaqil va parallel
bajariladi. Umumiy latency ularning yig‘indisi emas, eng sekin providerga yaqin
bo‘ladi. Provider implementatsiyasi environment mode orqali Nest injection
vaqtida tanlanadi. Noma’lum mode servisni ishga tushirmaydi; xavfsizlikka oid
konfiguratsiya xatosi mock provider bilan yashirilmaydi.

Canonical request tayyor subject/risk/device qiymatlarini ishonchli deb qabul
qiladi va identity verificationni chetlab o‘tadi. Shu sabab u faqat lokal test
uchun; production overlay uni majburan o‘chiradi.

## PEP evidence va PDP enrichment mas’uliyati

PEP xavfsizlik ma’lumotlarining yakuniy haqiqat manbasi emas. U foydalanuvchi
requestidan mavjud dalil va identifikatorlarni yig‘ib, PDP’ga yuboradi:

- foydalanuvchining JWT access tokeni;
- client IP manzili;
- `device_id`, `hostname` va `agent_id` kabi qurilma identifikatorlari;
- so‘ralgan resource va bajariladigan `read`, `write` yoki `delete` amali.

PDP Context Builder bu evidence’ni ishonchli tashqi manbalar orqali boyitadi va
tekshiradi:

| Signal | PEP yuboradi | PDP tekshiradigan manba |
| --- | --- | --- |
| Identity | JWT token | Keycloak/OIDC issuer, audience, JWKS |
| Device | ID, hostname, agent ID | Wazuh agent posture |
| Network | Client IP | MISP threat intelligence va Wazuh alertlari |
| Resource | Resource ID | OPA enterprise data |
| Action | HTTP requestdan hosil qilingan amal | OPA role/resource policy |

Shu modelda PEP’ning “qurilma xavfsiz” degan da’vosiga to‘g‘ridan-to‘g‘ri
ishonilmaydi. PEP faqat qurilmani topish uchun evidence beradi; managed holati,
EDR statusi, patch darajasi va zaifliklar Wazuh’dan olinadi.

Risk oqimi quyidagicha:

1. MISP source IP bo‘yicha IOC qidiradi va match bo‘lsa
   `threat_intel_match=true` signalini beradi.
2. Wazuh so‘nggi SIEM alertlari va device posture’dan risk signallarini beradi.
3. PDP signallarni canonical `risk` contextga birlashtiradi.
4. OPA risk threshold, role, department, MFA, device va resource policy’larini
   birgalikda baholab `allow` yoki `deny` chiqaradi.
5. Policy Administrator qarorni PEP uchun `permit` yoki `block` ko‘rsatmasiga
   aylantiradi.

Demak, PDP risk signallarini yig‘adi va normalizatsiya qiladi; yakuniy access
qarorini policy asosida OPA chiqaradi.

### Hozirgi runtime holati

2026-07-30 holatiga ko‘ra:

- Keycloak/OIDC identity tekshiruvi aktiv;
- MISP real threat-intelligence provider sifatida aktiv;
- OPA resource va policy evaluation aktiv;
- Wazuh adapterlari kodda tayyor, ammo Server API/Indexer endpointlari va
  credentiallar berilmagani sabab runtime’da aktiv emas;
- Wazuh yoqilmaguncha device posture mock provider orqali olinadi.

Wazuh ulangach `DEVICE_MODE=wazuh` va `RISK_MODE=wazuh-misp` ishlatiladi. Shunda
device posture hamda SIEM risk Wazuh’dan, threat-intelligence esa MISP’dan
keladi.

## Login, Keycloak va Single Sign-On

Hozirgi runtime konfiguratsiyasida foydalanuvchi logini Keycloak orqali amalga
oshadi. Foydalanuvchi PDP yoki OPA’ga bevosita login qilmaydi:

```text
Foydalanuvchi → PEP → Keycloak login → token → PEP → PDP/OPA qarori
```

Bu yerda authentication va authorization alohida vazifalardir:

- **Keycloak authentication qiladi** — foydalanuvchi kimligini tekshiradi va
  signed OIDC token beradi.
- **PDP context yig‘adi** — token, IP, device, risk va resource ma’lumotlarini
  tekshiradi va normalizatsiya qiladi.
- **OPA authorization qiladi** — barcha context va policy asosida `allow` yoki
  `deny` qarorini chiqaradi.
- **PEP enforcement qiladi** — `allow` bo‘lsa requestni ilovaga uzatadi,
  `deny` bo‘lsa bloklaydi.

Demak, login faqat Keycloak’dan o‘tishi mumkin, ammo access qarorini Keycloak
yakka o‘zi bermaydi.

### Bir nechta tizim uchun SSO

CRM, SIEM, ichki portal yoki boshqa himoyalangan tizimlar bir PEP yoki alohida
PEP instancelari orqasiga joylashtirilishi mumkin. Ularning barchasi bir xil
Keycloak realm’dan foydalansa, foydalanuvchi bir marta login qiladi:

```text
CRM portal ─────┐
SIEM panel ─────┼→ PEP layer → Keycloak SSO
Ichki API ──────┘                    |
                                     `→ PDP → MISP/Wazuh → OPA
```

Har bir tizim OPA data ichida alohida `resource_id` sifatida ro‘yxatdan
o‘tkaziladi. Keycloak umumiy login sessiyasini beradi, OPA esa foydalanuvchining
har bir resource va action uchun alohida huquqini tekshiradi.

### Keycloak o‘rniga boshqa Identity Provider

Arxitektura Keycloak’ga qattiq bog‘lanmagan; u standart OIDC/JWT adapteridan
foydalanadi. Keycloak quyidagi OIDC-compatible providerlardan biri bilan
almashtirilishi mumkin:

- Microsoft Entra ID;
- Okta;
- Auth0;
- mavjud korporativ Keycloak;
- boshqa OIDC-compatible Identity Provider.

Bunda PEP authorization/token/logout endpointlari, PDP’da esa issuer, audience,
JWKS URL va claim mapping konfiguratsiyasi almashtiriladi. MISP, Wazuh, OPA va
Policy Administrator arxitekturasi o‘zgarmaydi.

Yangi IdP’ga o‘tishda kamida quyidagilar sozlanadi:

```text
OIDC_ISSUER
OIDC_JWKS_URL
OIDC_AUDIENCE
OIDC_AUTH_URL
OIDC_TOKEN_URL
OIDC_LOGOUT_URL
OIDC_CLIENT_ID
OIDC_CLIENT_SECRET
```

Role, department va MFA boshqa claim nomlarida kelsa `OIDC_CLAIM_*`
parametrlari orqali canonical subject formatiga map qilinadi.

### PEP login qilgan foydalanuvchini qanday taniydi

PEP foydalanuvchini Keycloak bergan access token bilan bog‘langan sessiya
orqali taniydi. Brauzer login oqimi quyidagicha:

1. Foydalanuvchi PEP orqali himoyalangan URL’ni ochadi.
2. PEP `pep_sid` session cookie mavjudligini tekshiradi.
3. Sessiya bo‘lmasa foydalanuvchini Keycloak authorization endpointiga
   yuboradi.
4. Keycloak login muvaffaqiyatli bo‘lgach PEP callback’iga authorization code
   qaytaradi.
5. PEP code’ni OIDC token endpointida access token’ga almashtiradi.
6. PEP token va minimal session ma’lumotini AES-256-GCM bilan shifrlangan,
   autentifikatsiyalangan `pep_sid` cookie ichida saqlaydi.
7. Keyingi requestlarda PEP cookie’ni decrypt qilib sessiya va access tokenni
   tiklaydi.

```text
Browser                 PEP                    Keycloak
   | GET /crm             |                         |
   |--------------------->|                         |
   |                      | session mavjud emas     |
   |<--- login redirect --|                         |
   |---------------- OIDC login ------------------->|
   |<------------- authorization code -------------|
   | code                 |                         |
   |--------------------->|---- code → token ------>|
   |                      |<--- access token -------|
   |<-- encrypted cookie -|                         |
```

PEP ikki client turini qo‘llab-quvvatlaydi:

- **Browser:** shifrlangan `pep_sid` cookie.
- **API client:** `Authorization: Bearer <access-token>` headeri.

PEP token payloadini interfeysda username ko‘rsatish uchun decode qilishi
mumkin, ammo bu qiymat authorization uchun ishonchli hisoblanmaydi. Har bir
himoyalangan requestda token PDP’ga yuboriladi. PDP OIDC/JWKS orqali:

- JWT imzosini;
- issuer qiymatini;
- audience qiymatini;
- tokenning amal qilish muddatini;
- role, department va MFA claimlarini

tekshiradi. Faqat shu tekshiruvdan keyin canonical subject hosil bo‘ladi va OPA
policy evaluation’ga beriladi. PDP minimal javobda tasdiqlangan `user` va
`role`ni PEP’ga qaytaradi; PEP upstream ilovaga aynan shu tasdiqlangan identity
ma’lumotlarini uzatadi.

```text
Browser cookie yoki Bearer token
              ↓
PEP → token/evidence → PDP → JWKS verification → OPA
              ↑                                  ↓
              `-------- permit yoki block -------'
```

### OPA Policy Engine

Policy kodi `opa/policies/zta.rego`, policy va resource ma’lumotlari
`opa/data/zta.json` ichida. PDP resource provider ham shu data faylini o‘qiydi,
ya’ni resource inventory uchun OPA data yagona manba hisoblanadi.

OPA requestlari `OPA_TIMEOUT_MS` bilan cheklangan. OPA javob bermasa PDP access
bermaydi. `/pdp/health/ready` endpointi OPA health holatini ham tekshiradi.

#### OPA va Rego o‘rtasidagi farq

OPA — tayyor policy evaluation engine. Rego esa OPA bajaradigan policy
dasturlash tilidir:

```text
OPA  → policy engine va runtime
Rego → OPA tushunadigan policy tili
```

Masalan, Node.js JavaScript’ni bajargani kabi OPA Rego policy’larini bajaradi.
OPA quyidagi umumiy imkoniyatlarni tayyor beradi:

- JSON input va data bilan ishlash;
- Rego evaluation runtime;
- HTTP decision API;
- built-in operator va funksiyalar;
- policy unit-test runner;
- decision log va bundle loading.

OPA loyiha biznes qoidalarini oldindan bilmaydi. Qaysi rol CRM’ga kirishi,
resource MFA talab qilishi, maksimal risk chegarasi yoki MISP match bo‘lganda
bloklash kerakligi loyiha tomonidan belgilanadi.

```text
OPA
 ├─ Rego engine va built-in funksiyalar — platformada tayyor
 └─ loyiha policy’lari — loyiha jamoasi yozadi
      ├─ opa/policies/zta.rego
      └─ opa/data/zta.json
```

#### `zta.rego` vazifasi

`opa/policies/zta.rego` PDP yuborgan canonical inputni enterprise policy data
bilan solishtirib, yakuniy `allow` yoki `deny` qarorini chiqaradi. U quyidagilarni
tekshiradi:

- role va resource ma’lummi;
- department rolga mosmi;
- role resource/action huquqiga egami;
- MFA talabi bajarilganmi;
- device managed, EDR va patch talablari bajarilganmi;
- SIEM risk global yoki resource chegarasidan oshganmi;
- MISP threat-intelligence match mavjudmi;
- impossible travel aniqlanganmi.

Blocking sabab mavjud bo‘lsa policy `deny`, barcha talablar bajarilsa `allow`
qarorini va mos `policyId`, nom, sabablar hamda risk score’ni qaytaradi.

#### `zta.json` vazifasi

`opa/data/zta.json` policy kodi emas; u Rego ishlatadigan enterprise
konfiguratsiya va authorization data’sidir. Unda quyidagilar saqlanadi:

- resource katalogi va criticality;
- MFA va device talablari;
- risk thresholdlar;
- role va departmentlar;
- har bir role uchun resource/action huquqlari;
- policy display nomlari.

Oddiy yangi tizim qo‘shilganda ko‘pincha Rego o‘zgarmaydi. Yangi resource va
role/action huquqlari `zta.json`ga qo‘shiladi. Standart model ifodalay olmaydigan
maxsus biznes qoida bo‘lsa Rego kengaytiriladi.

#### Rego testlari

`opa/policies/zta_test.rego` asosiy policy uchun avtomatik testlarni saqlaydi.
Testlar allow, yuqori risk, noma’lum role, threat-intelligence match va
impossible-travel kabi qarorlarni tekshiradi:

```bash
npm run test:opa
```

2026-07-29 verifikatsiyasida mavjud testlar `PASS: 5/5` natija bilan o‘tgan.
Policy yoki `zta.json` strukturasi o‘zgarsa tegishli allow va deny regression
testlari ham yangilanishi kerak.

### Policy Administrator

OPA `allow` qarori `permit`ga, `deny` qarori `block`ka aylanadi. Allow TTL risk
oshgani sari 900, 600 yoki 300 soniyaga kamayadi. Deny TTL har doim `0`.
Yuqori risk, threat-intel match va impossible-travel security notification
obligationini hosil qiladi.

### Audit

Har qaror JSONL audit yozuviga aylanadi. Yozish serialized asynchronous queue
orqali bajariladi va fayl `PDP_AUDIT_MAX_BYTES` chegarasida rotatsiya qilinadi.

- `PDP_AUDIT_REQUIRED=true`: audit saqlanmasa qaror clientga qaytarilmaydi.
- `PDP_AUDIT_HMAC_SECRET`: har yozuvga SHA-256 HMAC integrity belgisi qo‘shadi.
- `PDP_AUDIT_WEBHOOK_URL`: yozuvni markaziy SIEM/collector’ga yuboradi.

Lokal JSONL operatsion qulaylik uchun qoladi; ko‘p replica production muhitida
webhook orqali markaziy collector asosiy audit destination bo‘lishi kerak.

## Ishonch chegaralari

| Chegara | Himoya |
| --- | --- |
| Browser → PEP | OIDC Authorization Code + PKCE, signed/encrypted cookie |
| API → PEP | Bearer access token; token PDP’da tekshiriladi |
| PEP → PDP | `X-PDP-Auth` shared secret; production’da network isolation |
| PDP → IdP | issuer, audience, signature va expiry tekshiruvi |
| PDP → OPA | ichki network, timeout, fail-closed |
| PEP → upstream | faqat `allow`; raw token upstream’ga berilmaydi |

Shared secret hozirgi minimal service-auth mexanizmidir. Katta yoki
multi-tenant deployment uchun keyingi evolyutsiya mTLS yoki qisqa muddatli
service JWT bo‘lishi kerak.

## Health endpointlari

- `/pdp/health` — backward-compatible oddiy health.
- `/pdp/health/live` — process tirikligini bildiradi.
- `/pdp/health/ready` — PDP traffic qabul qilishi va OPA tayyorligini tekshiradi.
- `/health` — PEP process health.

## Source tree xaritasi

| Path | Mas’uliyat |
| --- | --- |
| `src/pdp/pdp.service.ts` | PDP orchestration |
| `src/pdp/context/` | canonical context va provider adapterlar |
| `src/pdp/policy-engine/` | OPA integratsiyasi |
| `src/pdp/policy-administrator/` | enforcement mapping va TTL |
| `src/pdp/audit/` | audit persistence va forwarding |
| `src/pdp/security/` | PDP service authentication |
| `src/pep/` | login, PDP client va reverse proxy enforcement |
| `opa/policies/` | Rego policy logic va testlar |
| `opa/data/` | enterprise policy/resource data |

## Arxitektura qoidalari

- Authorization faqat PEP orqali enforce qilinadi.
- PDP/OPA portlari production’da public host’ga chiqarilmaydi.
- Har qanday dependency xatosi access uchun deny/error natija beradi.
- Mock va canonical input production’da ishlatilmaydi.
- Policy logic TypeScript ichiga ko‘chirilmaydi; OPA policy sifatida qoladi.
- Yangi context manbasi mavjud provider interface orqali qo‘shiladi.
- Public response minimal, ichki trace esa faqat development uchun.
