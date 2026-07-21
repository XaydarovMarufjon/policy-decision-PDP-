/**
 * PEP — Policy Enforcement Point (demo gateway).
 *
 * Closes the Zero Trust loop: a user logs in through Keycloak (OIDC
 * authorization-code + PKCE) in the browser, then every request to a protected
 * resource is authorized by the PDP before the PEP serves it.
 *
 *   Browser --login--> Keycloak --token--> PEP session
 *   Browser --request--> PEP --evidence(+token)--> PDP --allow/deny--> PEP
 *                                                         permit -> serve
 *                                                         block  -> 403
 *
 * Two entry modes:
 *   - Browser: session cookie established via /login -> /callback.
 *   - API:     `Authorization: Bearer <access_token>` (e.g. from kc-token.sh),
 *              returns JSON instead of HTML.
 */
import { createHash, randomBytes } from 'crypto';
import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';

const PORT = Number(process.env.PEP_PORT ?? 8000);
const PDP_EVALUATE_URL =
  process.env.PDP_EVALUATE_URL ?? 'http://pdp:3000/pdp/evaluate';
const OIDC_AUTH_URL =
  process.env.OIDC_AUTH_URL ??
  'http://localhost:8080/realms/soc/protocol/openid-connect/auth';
const OIDC_TOKEN_URL =
  process.env.OIDC_TOKEN_URL ??
  'http://keycloak:8080/realms/soc/protocol/openid-connect/token';
const OIDC_LOGOUT_URL =
  process.env.OIDC_LOGOUT_URL ??
  'http://localhost:8080/realms/soc/protocol/openid-connect/logout';
const CLIENT_ID = process.env.OIDC_CLIENT_ID ?? 'pdp-pep';
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET ?? 'pep-dev-secret';
const REDIRECT_URI =
  process.env.PEP_REDIRECT_URI ?? 'http://localhost:8000/callback';
const BASE_URL = process.env.PEP_BASE_URL ?? 'http://localhost:8000';
const COOKIE_SECRET =
  process.env.COOKIE_SECRET ?? 'pep-dev-cookie-secret-change-me';

interface Session {
  accessToken: string;
  idToken?: string;
  username: string;
}

// Single-instance in-memory session store (demo). A real PEP uses Redis/JWT.
const sessions = new Map<string, Session>();

const b64url = (buf: Buffer): string =>
  buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const randomToken = (): string => b64url(randomBytes(32));

const sha256 = (value: string): Buffer => createHash('sha256').update(value).digest();

/** Decode a JWT payload without verification (display only; PDP verifies). */
function decodeJwt(token: string): Record<string, unknown> {
  try {
    const part = token.split('.')[1];
    const json = Buffer.from(part, 'base64url').toString('utf8');
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

const app = Fastify({ logger: true });
app.register(cookie, { secret: COOKIE_SECRET });

/** Resolve the caller's access token: Bearer header (API) or session (browser). */
function resolveToken(
  request: FastifyRequest,
): { token: string; api: boolean; session?: Session } | null {
  const auth = request.headers.authorization;
  if (auth?.startsWith('Bearer ')) {
    return { token: auth.slice(7), api: true };
  }

  const raw = request.cookies['pep_sid'];
  if (raw) {
    const unsigned = request.unsignCookie(raw);
    if (unsigned.valid && unsigned.value) {
      const session = sessions.get(unsigned.value);
      if (session) {
        return { token: session.accessToken, api: false, session };
      }
    }
  }

  return null;
}

/** Build the canonical evidence request the PDP expects. */
function buildEvidence(token: string, resourceId: string, action: string): unknown {
  return {
    request_id: `pep-${randomToken().slice(0, 8)}`,
    request_metadata: { client: 'pep-gateway', received_at: undefined },
    subject_ref: { type: 'jwt', token },
    device_evidence: {
      device_id: 'device-456',
      hostname: 'soc-laptop-456',
      agent_id: 'wazuh-agent-456',
      os: 'Ubuntu',
      os_version: '24.04',
      browser: 'Chrome 126',
      certificate_fingerprint: 'sha256:pep-device-cert',
    },
    network: {
      source_ip: '10.10.80.55',
      source_port: 54822,
      protocol: 'https',
      geo_country: 'UZ',
      network_zone: 'corp-vpn',
    },
    resource_ref: {
      resource_id: resourceId,
      path: `/api/${resourceId}`,
      environment: 'production',
      tenant_id: 'soc',
    },
    action,
  };
}

interface RouteStep {
  order: number;
  stage: string;
  title: string;
  status: string;
  description?: string;
  input?: unknown;
  process?: unknown;
  output?: unknown;
}

interface TraceEntry {
  source: string;
  adapter: string;
  operation: string;
  lookupKey: string;
  status: string;
  durationMs: number;
  result?: unknown;
  error?: string;
}

interface PdpResult {
  ok: boolean;
  decision?: string;
  reason?: string[];
  subject?: Record<string, unknown>;
  enforce?: string;
  route?: RouteStep[];
  trace?: TraceEntry[];
  error?: string;
  status: number;
}

async function askPdp(
  token: string,
  resourceId: string,
  action: string,
): Promise<PdpResult> {
  const res = await fetch(PDP_EVALUATE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(buildEvidence(token, resourceId, action)),
  });
  const body = (await res.json()) as Record<string, unknown>;

  if (!res.ok || typeof body.decision !== 'string') {
    return {
      ok: false,
      error: (body.message as string) ?? `PDP error (HTTP ${res.status})`,
      status: res.status === 200 ? 400 : res.status,
    };
  }

  const decision = body.decision as string;
  const context = body.context as {
    canonicalInput?: { subject?: Record<string, unknown> };
    trace?: TraceEntry[];
  };
  const pa = body.pa as { enforcementCommand?: string };
  return {
    ok: true,
    decision,
    reason: body.reason as string[],
    subject: context?.canonicalInput?.subject,
    enforce: pa?.enforcementCommand,
    route: body.route as RouteStep[],
    trace: context?.trace,
    status: decision === 'allow' ? 200 : 403,
  };
}

// ---- Routes -----------------------------------------------------------------

app.get('/health', async () => ({ status: 'ok', service: 'pep' }));

app.get('/login', async (request, reply) => {
  const state = randomToken();
  const verifier = randomToken();
  const challenge = b64url(sha256(verifier));
  const returnTo = (request.query as { returnTo?: string }).returnTo ?? '/';

  reply.setCookie(
    'pep_flow',
    JSON.stringify({ state, verifier, returnTo }),
    { signed: true, httpOnly: true, path: '/', maxAge: 600, sameSite: 'lax' },
  );

  const url = new URL(OIDC_AUTH_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return reply.redirect(url.toString());
});

app.get('/callback', async (request, reply) => {
  const { code, state } = request.query as { code?: string; state?: string };
  const raw = request.cookies['pep_flow'];
  const unsigned = raw ? request.unsignCookie(raw) : { valid: false, value: null };

  if (!code || !state || !unsigned.valid || !unsigned.value) {
    return reply.code(400).type('text/html').send(page('Login xatosi', errorCard('Yaroqsiz login callback (state/flow topilmadi).')));
  }

  const flow = JSON.parse(unsigned.value) as { state: string; verifier: string; returnTo: string };
  if (flow.state !== state) {
    return reply.code(400).type('text/html').send(page('Login xatosi', errorCard('State mos kelmadi (CSRF himoyasi).')));
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code_verifier: flow.verifier,
  });
  const tokenRes = await fetch(OIDC_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const tokens = (await tokenRes.json()) as {
    access_token?: string;
    id_token?: string;
    error_description?: string;
  };

  if (!tokenRes.ok || !tokens.access_token) {
    return reply
      .code(400)
      .type('text/html')
      .send(page('Login xatosi', errorCard(`Token almashinuvi muvaffaqiyatsiz: ${tokens.error_description ?? tokenRes.status}`)));
  }

  const claims = decodeJwt(tokens.access_token);
  const sid = randomToken();
  sessions.set(sid, {
    accessToken: tokens.access_token,
    idToken: tokens.id_token,
    username: (claims.preferred_username as string) ?? 'user',
  });

  reply.clearCookie('pep_flow', { path: '/' });
  reply.setCookie('pep_sid', sid, {
    signed: true,
    httpOnly: true,
    path: '/',
    sameSite: 'lax',
  });
  return reply.redirect(flow.returnTo || '/');
});

app.get('/logout', async (request, reply) => {
  const raw = request.cookies['pep_sid'];
  let idToken: string | undefined;
  if (raw) {
    const unsigned = request.unsignCookie(raw);
    if (unsigned.valid && unsigned.value) {
      idToken = sessions.get(unsigned.value)?.idToken;
      sessions.delete(unsigned.value);
    }
  }
  reply.clearCookie('pep_sid', { path: '/' });

  const url = new URL(OIDC_LOGOUT_URL);
  url.searchParams.set('post_logout_redirect_uri', `${BASE_URL}/`);
  if (idToken) {
    url.searchParams.set('id_token_hint', idToken);
  }
  return reply.redirect(url.toString());
});

app.get('/', async (request, reply) => {
  const q = request.query as { resource?: string; action?: string };
  const resource = q.resource ?? 'incident_db';
  const action = q.action ?? 'read';

  const resolved = resolveToken(request);
  if (!resolved) {
    // Browser: no session -> start login. (API clients get 401.)
    if (request.headers.authorization) {
      return reply.code(401).send({ error: 'missing or invalid Bearer token' });
    }
    return reply.redirect(`/login?returnTo=${encodeURIComponent(request.url)}`);
  }

  const result = await askPdp(resolved.token, resource, action);

  // Wrap the PDP's internal route with the PEP's own enforcement steps so the
  // page shows the full Zero Trust chain: PEP -> PDP -> PEP enforcement.
  if (result.ok) {
    const who =
      resolved.session?.username ?? (result.subject?.user as string) ?? 'user';
    result.route = withPepSteps(result, resolved.api, who, resource, action);
  }

  if (resolved.api) {
    return reply.code(result.status).send(result);
  }

  const username = resolved.session?.username ?? 'user';
  return reply
    .code(result.status)
    .type('text/html')
    .send(page('PEP — Protected Resource', resourceCard(username, resource, action, result)));
});

// ---- HTML -------------------------------------------------------------------

const RESOURCES = ['incident_db', 'case_management', 'audit_log'];
const ACTIONS = ['read', 'write', 'delete'];

function nav(resource: string, action: string): string {
  const links = RESOURCES.flatMap((r) =>
    ACTIONS.map((a) => {
      const active = r === resource && a === action ? ' class="active"' : '';
      return `<a${active} href="/?resource=${r}&action=${a}">${r}:${a}</a>`;
    }),
  ).join('');
  return `<div class="nav">${links}</div>`;
}

function resourceCard(
  username: string,
  resource: string,
  action: string,
  result: PdpResult,
): string {
  if (!result.ok) {
    return `${topbar(username)}${nav(resource, action)}${errorCard(result.error ?? 'PDP error')}`;
  }
  const allow = result.decision === 'allow';
  const badge = allow
    ? '<span class="badge allow">✔ ACCESS GRANTED</span>'
    : '<span class="badge deny">✘ ACCESS DENIED</span>';
  const reasons = (result.reason ?? []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  const data = allow
    ? `<div class="data"><h3>${resource} · ${action}</h3><p>🔓 Bu himoyalangan resurs — PDP ruxsat berdi. (namunaviy ma'lumot)</p></div>`
    : '';
  return `
    ${topbar(username)}
    ${nav(resource, action)}
    <div class="card ${allow ? 'ok' : 'bad'}">
      ${badge}
      <div class="meta">
        <div><b>resource</b> ${resource}</div>
        <div><b>action</b> ${action}</div>
        <div><b>enforce</b> ${result.enforce ?? '-'}</div>
      </div>
      <div class="subject"><b>subject:</b> ${escapeHtml(JSON.stringify(result.subject ?? {}))}</div>
      <div class="reasons"><b>PDP reason</b><ul>${reasons}</ul></div>
      ${data}
    </div>
    ${renderRoute(result.route)}
    ${renderTrace(result.trace)}`;
}

function statusDot(status: string): string {
  const cls = status === 'ok' ? 'ok' : status === 'miss' ? 'miss' : 'err';
  return `<span class="dot ${cls}"></span>`;
}

/** Bracket the PDP route with the PEP's own request + enforcement steps. */
function withPepSteps(
  result: PdpResult,
  api: boolean,
  user: string,
  resource: string,
  action: string,
): RouteStep[] {
  const pdp = result.route ?? [];
  const allow = result.decision === 'allow';

  const pre: RouteStep = {
    order: 0,
    stage: 'pep_request',
    title: 'PEP so‘rovni ushladi',
    status: 'ok',
    description: `PEP gateway so‘rovni ushlab, ${
      api ? 'Authorization: Bearer token' : 'brauzer sessiya cookie'
    } orqali foydalanuvchi tokenini oldi va PDP ga evidence yubordi.`,
    process: {
      mode: api ? 'api (bearer)' : 'browser (session)',
      user,
      resource,
      action,
      pdpEndpoint: PDP_EVALUATE_URL,
    },
  };

  const post: RouteStep = {
    order: pdp.length + 1,
    stage: 'pep_enforcement',
    title: 'PEP qarorni bajardi',
    status: allow ? 'ok' : 'err',
    description: allow
      ? `permit → resurs (${resource}:${action}) foydalanuvchiga berildi (HTTP ${result.status}).`
      : `block → kirish rad etildi (HTTP ${result.status}).`,
    process: { enforcement: result.enforce, httpStatus: result.status },
  };

  return [pre, ...pdp, post];
}

function renderRoute(route?: RouteStep[]): string {
  if (!route?.length) return '';
  const steps = route
    .map((s) => {
      const details = JSON.stringify(
        { input: s.input, process: s.process, output: s.output },
        null,
        2,
      );
      const isPep = typeof s.stage === 'string' && s.stage.indexOf('pep_') === 0;
      return `
      <div class="step${isPep ? ' pep' : ''}">
        <div class="step-h">${statusDot(s.status)}<span class="ord">${isPep ? '◆' : s.order}</span>
          <span class="stitle">${isPep ? '<span class="pepbadge">PEP</span> ' : ''}${escapeHtml(s.title)}</span>
          <span class="stage">${escapeHtml(s.stage)}</span></div>
        ${s.description ? `<div class="sdesc">${escapeHtml(s.description)}</div>` : ''}
        <details><summary>input / process / output</summary><pre>${escapeHtml(details)}</pre></details>
      </div>`;
    })
    .join('');
  return `<div class="card route"><h2>ROUTE — qaror yo'li</h2>${steps}</div>`;
}

function renderTrace(trace?: TraceEntry[]): string {
  if (!trace?.length) return '';
  const rows = trace
    .map(
      (t) => `<tr>
        <td>${statusDot(t.status)}${escapeHtml(t.source)}</td>
        <td>${escapeHtml(t.adapter)}</td>
        <td>${escapeHtml(t.lookupKey)}</td>
        <td>${t.durationMs}ms</td>
        <td class="tres">${escapeHtml(JSON.stringify(t.result ?? t.error ?? ''))}</td>
      </tr>`,
    )
    .join('');
  return `<div class="card trace"><h2>CONTEXT TRACE — qaysi manbadan</h2>
    <table><thead><tr><th>source</th><th>adapter</th><th>key</th><th>dur</th><th>result</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function topbar(username: string): string {
  return `<div class="topbar"><div>👤 <b>${escapeHtml(username)}</b> — logged in via Keycloak</div><a class="logout" href="/logout">Logout</a></div>`;
}

function errorCard(msg: string): string {
  return `<div class="card bad"><span class="badge deny">⚠ ERROR</span><p>${escapeHtml(msg)}</p></div>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
  <style>
    body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
    .wrap{max-width:820px;margin:0 auto;padding:24px}
    h1{font-size:18px;color:#94a3b8;font-weight:600}
    .topbar{display:flex;justify-content:space-between;align-items:center;background:#1e293b;padding:12px 16px;border-radius:10px;margin-bottom:14px}
    .logout{color:#f87171;text-decoration:none;font-size:13px;border:1px solid #f87171;padding:4px 10px;border-radius:6px}
    .nav{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
    .nav a{font-size:12px;color:#cbd5e1;background:#1e293b;padding:5px 9px;border-radius:6px;text-decoration:none;border:1px solid #334155}
    .nav a.active{background:#2563eb;border-color:#2563eb;color:#fff}
    .card{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}
    .card.ok{border-color:#16a34a}.card.bad{border-color:#dc2626}
    .badge{display:inline-block;padding:6px 12px;border-radius:8px;font-weight:700;font-size:14px}
    .badge.allow{background:#052e16;color:#4ade80}.badge.deny{background:#450a0a;color:#f87171}
    .meta{display:flex;gap:20px;margin:16px 0;font-size:13px;color:#cbd5e1}
    .subject{font-family:ui-monospace,monospace;font-size:12px;color:#93c5fd;margin-bottom:12px;word-break:break-all}
    .reasons ul{margin:6px 0 0;padding-left:18px;font-size:13px}
    .data{margin-top:16px;padding:16px;background:#052e16;border-radius:8px;color:#bbf7d0}
    a.login{display:inline-block;background:#2563eb;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none}
    .card.route,.card.trace{margin-top:14px}
    .card h2{font-size:13px;color:#94a3b8;margin:0 0 12px;letter-spacing:.5px}
    .step{border-left:2px solid #334155;padding:0 0 14px 14px;margin-left:6px;position:relative}
    .step:last-child{padding-bottom:0}
    .step.pep{border-left-color:#2563eb}
    .step.pep .ord{background:#2563eb;color:#fff}
    .pepbadge{background:#2563eb;color:#fff;font-size:9px;font-weight:700;padding:1px 5px;border-radius:4px;margin-right:4px;vertical-align:middle;letter-spacing:.5px}
    .step-h{display:flex;align-items:center;gap:8px;font-size:13px}
    .ord{background:#334155;color:#cbd5e1;width:20px;height:20px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:11px}
    .stitle{font-weight:600;color:#e2e8f0}
    .stage{margin-left:auto;font-size:11px;color:#64748b;font-family:ui-monospace,monospace}
    .sdesc{font-size:12px;color:#94a3b8;margin:4px 0 6px 28px}
    details{margin:4px 0 0 28px}
    summary{font-size:11px;color:#60a5fa;cursor:pointer}
    pre{background:#0b1220;border:1px solid #1e293b;border-radius:6px;padding:10px;font-size:11px;overflow-x:auto;color:#cbd5e1}
    .dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:0 0 auto}
    .dot.ok{background:#22c55e}.dot.miss{background:#eab308}.dot.err{background:#ef4444}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #1e293b;vertical-align:top}
    th{color:#64748b;font-weight:600}
    td .dot{margin-right:6px}
    .tres{font-family:ui-monospace,monospace;color:#93c5fd;max-width:280px;word-break:break-all}
  </style></head><body><div class="wrap"><h1>SentryX PEP · Zero Trust Gateway</h1>${body}</div></body></html>`;
}

app
  .listen({ port: PORT, host: '0.0.0.0' })
  .then(() => app.log.info(`PEP gateway listening on ${PORT}, PDP=${PDP_EVALUATE_URL}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
