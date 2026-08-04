# Himoyalangan tizimlarni integratsiya qilish

Ushbu qo‘llanma CRM, SIEM, ichki portal, web-ilova yoki API’ni PEP/PDP
arxitekturasiga ulash tartibini tushuntiradi.

## Integratsiya modeli

Himoyalanadigan ilova public port orqali bevosita ochilmaydi. Foydalanuvchi
faqat PEP orqali kiradi:

```text
Foydalanuvchi
      |
      v
PEP Gateway → Keycloak login
      |
      +→ PDP → MISP/Wazuh → OPA
      |
      | faqat allow
      v
Himoyalangan ilova
```

PEP’ni chetlab o‘tib ilovaga kirish imkoni bo‘lsa, authorization himoyasi to‘liq
ishlamaydi. Shu sabab upstream ilova PEP bilan bir private network’da bo‘lishi
va host’ga alohida port publish qilmasligi kerak.

## Hozirgi implementatsiya: bitta upstream

Hozirgi PEP `/app/*` prefix ostida bitta upstream tizimni qo‘llab-quvvatlaydi:

```text
/app/* → APP_UPSTREAM_URL
```

Kerakli environment sozlamalari:

```text
APP_UPSTREAM_URL=http://crm:5000
APP_RESOURCE_ID=crm
```

Foydalanuvchi CRM’ni quyidagi manzilda ochadi:

```text
http://localhost:8000/app/
```

## 1. Ilovani private network’ga qo‘shish

Masalan, yangi CRM uchun Compose override:

```yaml
services:
  crm:
    image: company/crm:latest
    expose:
      - "5000"
    restart: unless-stopped

  pep:
    environment:
      APP_UPSTREAM_URL: "http://crm:5000"
      APP_RESOURCE_ID: "crm"
    depends_on:
      - crm
```

`expose` portni faqat Compose network ichida ko‘rsatadi. Quyidagi konfiguratsiya
production’da ishlatilmasligi kerak:

```yaml
# Xavfli: foydalanuvchi PEP’ni chetlab o‘tishi mumkin.
ports:
  - "5000:5000"
```

## 2. Resource’ni OPA data’ga qo‘shish

`opa/data/zta.json` ichidagi `enterprise.zta.resources` bo‘limiga yangi tizim
qo‘shiladi:

```json
{
  "crm": {
    "type": "web_application",
    "criticality": "high",
    "required_mfa": true,
    "max_risk_score": 40,
    "device": {
      "managed": true,
      "edr_status": "healthy",
      "patch_level": "current"
    }
  }
}
```

Bu yerda `crm` — PEP yuboradigan `resource_id` bilan bir xil bo‘lishi kerak.

## 3. Role va action huquqlarini belgilash

Shu fayldagi `enterprise.zta.roles` bo‘limida har bir rol uchun huquq beriladi:

```json
{
  "analyst": {
    "departments": ["SOC"],
    "resources": {
      "crm": ["read"]
    }
  },
  "admin": {
    "departments": ["SOC", "IT"],
    "resources": {
      "crm": ["read", "write", "delete"]
    }
  }
}
```

PEP HTTP metodini canonical action’ga aylantiradi:

| HTTP metod | OPA action |
| --- | --- |
| `GET`, `HEAD` | `read` |
| `POST`, `PUT`, `PATCH` | `write` |
| `DELETE` | `delete` |

## 4. Stackni qayta ishga tushirish

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.keycloak.yml \
  -f docker-compose.pep.yml \
  -f docker-compose.misp.yml \
  -f docker-compose.crm.yml \
  up -d --build
```

OPA data o‘zgargandan keyin OPA va PDP yangi konfiguratsiyani yuklashi kerak.

## 5. Request va qaror oqimi

Masalan, foydalanuvchi CRM’da `POST /app/customers` yuborsa:

```text
PEP route       → resource_id=crm
HTTP POST       → action=write
Browser session → access token
Request socket  → source IP
Device evidence → hostname/agent identifier
```

PDP identity, device, risk va resource contextni yig‘adi. OPA `crm:write`
huquqini tekshiradi. Faqat `allow` bo‘lsa PEP requestni CRM’ga uzatadi.

## Upstream identity headerlari

PEP raw access tokenni upstream’ga uzatmaydi. PDP tomonidan tasdiqlangan identity
asosida quyidagi headerlarni beradi:

```http
X-User: ali.valiyev
X-Role: analyst
X-Forwarded-Prefix: /app
X-Forwarded-For: 203.0.113.10
```

Upstream bu headerlarga faqat quyidagi shartlarda ishonishi mumkin:

- upstream public network’dan yopiq;
- request faqat PEP container/network identity’sidan keladi;
- tashqi client yuborgan identity headerlari PEP tomonidan almashtiriladi;
- PEP va upstream orasida production network policy mavjud.

## Bir nechta tizim integratsiyasi

Bir nechta tizimni bir vaqtda ulash uchun PEP route registry talab qilinadi:

```json
[
  {
    "prefix": "/crm",
    "resourceId": "crm",
    "upstream": "http://crm:5000"
  },
  {
    "prefix": "/siem",
    "resourceId": "siem",
    "upstream": "http://siem:5601"
  },
  {
    "prefix": "/portal",
    "resourceId": "portal",
    "upstream": "http://portal:8080"
  }
]
```

Kutiladigan tashqi manzillar:

```text
http://localhost:8000/crm/
http://localhost:8000/siem/
http://localhost:8000/portal/
```

Hozirgi kod route registry’ni hali implementatsiya qilmagan; `/app/*` bitta
upstream bilan ishlaydi. Yangi tizim avtomatik aniqlanmasligi xavfsizlik talabi:
har bir prefix, upstream, resource ID va OPA huquqi oldindan ro‘yxatdan o‘tadi.
Noma’lum route default holatda bloklanishi kerak.

## Integratsiya checklist

- [ ] Ilova PEP bilan private network’da.
- [ ] Ilovaning public host porti yopilgan.
- [ ] `APP_UPSTREAM_URL` to‘g‘ri.
- [ ] `APP_RESOURCE_ID` OPA resource ID bilan bir xil.
- [ ] Resource `zta.json`ga qo‘shilgan.
- [ ] Role/action huquqlari belgilangan.
- [ ] MFA, device va risk talablari tanlangan.
- [ ] Allow va deny holatlari test qilingan.
- [ ] Upstream identity headerlarini faqat PEP’dan qabul qiladi.
- [ ] Audit logda qaror va resource ko‘rinadi.
