/**
 * Demo protected web-app ("my_app") — the system the PEP protects.
 *
 * Deliberately knows NOTHING about Zero Trust: no login, no tokens, no PDP.
 * It only trusts two headers the PEP sets after the PDP verified the caller:
 *
 *   X-User             verified username (from the JWT the PDP validated)
 *   X-Role             verified role
 *   X-Forwarded-Prefix path prefix the PEP serves this app under (/app)
 *
 * It must never be exposed directly — no published ports in compose; it is
 * reachable only through the PEP on the internal docker network.
 *
 *   GET    /              HTML page (notes UI)
 *   GET    /api/notes     list notes            (PEP maps GET    -> read)
 *   POST   /api/notes     add a note            (PEP maps POST   -> write)
 *   DELETE /api/notes/:id remove a note         (PEP maps DELETE -> delete)
 */
import Fastify from 'fastify';

const PORT = Number(process.env.APP_PORT ?? 5000);

interface Note {
  id: number;
  text: string;
  author: string;
}

// In-memory store (demo).
let nextId = 3;
let notes: Note[] = [
  { id: 1, text: 'Server xonasidagi kameralarni tekshirish', author: 'system' },
  { id: 2, text: 'Haftalik SOC hisobotini tayyorlash', author: 'system' },
];

const app = Fastify({ logger: true });

const escapeHtml = (s: string): string =>
  s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));

const headerValue = (v: string | string[] | undefined): string =>
  (Array.isArray(v) ? v[0] : v) ?? '';

app.get('/health', async () => ({ status: 'ok', service: 'demo-app' }));

app.get('/api/notes', async () => ({ notes }));

app.post('/api/notes', async (request, reply) => {
  const body = request.body as { text?: string } | null;
  const text = body?.text?.trim();
  if (!text) {
    return reply.code(400).send({ error: 'text is required' });
  }
  const note: Note = {
    id: nextId++,
    text,
    author: headerValue(request.headers['x-user']) || 'anonymous',
  };
  notes.push(note);
  return reply.code(201).send({ note });
});

app.delete('/api/notes/:id', async (request, reply) => {
  const id = Number((request.params as { id: string }).id);
  const before = notes.length;
  notes = notes.filter((n) => n.id !== id);
  if (notes.length === before) {
    return reply.code(404).send({ error: 'note not found' });
  }
  return { deleted: id };
});

app.get('/', async (request, reply) => {
  const user = headerValue(request.headers['x-user']) || 'anonymous';
  const role = headerValue(request.headers['x-role']) || '-';
  const prefix = headerValue(request.headers['x-forwarded-prefix']);
  return reply.type('text/html').send(pageHtml(user, role, prefix));
});

function pageHtml(user: string, role: string, prefix: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>my_app — Notes</title>
  <style>
    body{font-family:system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
    .wrap{max-width:640px;margin:0 auto;padding:24px}
    h1{font-size:18px;color:#94a3b8;font-weight:600}
    .who{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px 16px;font-size:13px;margin-bottom:16px}
    .who b{color:#93c5fd}
    .note{display:flex;align-items:center;gap:10px;background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px 16px;margin-bottom:8px}
    .note .txt{flex:1}
    .note .by{font-size:11px;color:#64748b}
    .note button{background:#450a0a;color:#f87171;border:1px solid #7f1d1d;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px}
    form{display:flex;gap:8px;margin:16px 0}
    input{flex:1;background:#0b1220;border:1px solid #334155;border-radius:8px;padding:10px;color:#e2e8f0;font-size:14px}
    form button{background:#2563eb;color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer}
    #banner{display:none;background:#450a0a;border:1px solid #dc2626;color:#f87171;border-radius:10px;padding:12px 16px;font-size:13px;margin-bottom:16px}
    #banner ul{margin:6px 0 0;padding-left:18px}
    .back{font-size:12px;color:#60a5fa;text-decoration:none}
  </style></head><body><div class="wrap">
  <h1>📝 my_app — Notes <span style="color:#475569;font-weight:400">(himoyalangan tizim, :5000)</span></h1>
  <div class="who">Siz: <b>${escapeHtml(user)}</b> · rol: <b>${escapeHtml(role)}</b> — bu ma'lumot PEP dan <code>X-User</code>/<code>X-Role</code> header sifatida keldi (PDP tekshirgan). <a class="back" href="/">← PEP sahifasiga</a></div>
  <div id="banner"></div>
  <form id="add"><input id="text" placeholder="Yangi eslatma... (POST → write)" autocomplete="off"><button>Qo'shish</button></form>
  <div id="notes"></div>
  <script>
    const PREFIX = ${JSON.stringify(prefix)};
    const api = (p) => PREFIX + p;

    function showDenied(action, body) {
      const el = document.getElementById('banner');
      const reasons = (body && body.reason ? body.reason : []).map((r) => '<li>' + r + '</li>').join('');
      el.innerHTML = '<b>✘ ZTA BLOKLADI</b> — "' + action + '" amali uchun PDP ruxsat bermadi (HTTP 403).<ul>' + reasons + '</ul>';
      el.style.display = 'block';
    }
    function hideBanner() { document.getElementById('banner').style.display = 'none'; }

    async function load() {
      const res = await fetch(api('/api/notes'));
      if (res.status === 403) { showDenied('read', await res.json()); return; }
      const data = await res.json();
      document.getElementById('notes').innerHTML = data.notes.map((n) =>
        '<div class="note"><span class="txt">' + n.text.replace(/</g, '&lt;') + '</span>' +
        '<span class="by">' + n.author + '</span>' +
        '<button onclick="delNote(' + n.id + ')">Delete</button></div>').join('');
    }
    async function addNote(e) {
      e.preventDefault();
      const input = document.getElementById('text');
      if (!input.value.trim()) return;
      const res = await fetch(api('/api/notes'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: input.value }),
      });
      if (res.status === 403) { showDenied('write', await res.json()); return; }
      hideBanner(); input.value = ''; load();
    }
    async function delNote(id) {
      const res = await fetch(api('/api/notes/' + id), { method: 'DELETE' });
      if (res.status === 403) { showDenied('delete', await res.json()); return; }
      hideBanner(); load();
    }
    document.getElementById('add').addEventListener('submit', addNote);
    load();
  </script></div></body></html>`;
}

app
  .listen({ port: PORT, host: '0.0.0.0' })
  .then(() => app.log.info(`demo-app (my_app) listening on ${PORT}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
