// Decoy cloud API. Pure request handler: no Cloudflare globals except what env gives us, so it tests under Node.
// env: { DB (D1), SALT, MAIL_FROM, PUBLIC_URL, RESEND_API_KEY }   deps: { mail(to, subject, text), now() }
export const FINDINGS = new Set(["grabber-endpoint", "password-third-party", "keystroke-leak", "brand-redirect", "skim-read", "clipboard-command"]);
const ALERT_KINDS = new Set(["likely", "grabber", "download", "entered"]);
export const MIN_CONFIRMATIONS = 3;
const MAX_GUARDIANS = 3;
const HOUR = 3600_000, DAY = 24 * HOUR;

const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", "access-control-allow-origin": "*", ...headers } });
const err = (status, msg) => json({ error: msg }, status);
const html = (body, status = 200) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Decoy</title><body style="font:16px/1.5 system-ui;max-width:520px;margin:12vh auto;padding:0 20px;color:#111">${body}</body>`, { status, headers: { "content-type": "text/html; charset=utf-8", "referrer-policy": "no-referrer" } });
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const enc = new TextEncoder();
async function sha256(s) { const d = await crypto.subtle.digest("SHA-256", enc.encode(s)); return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join(""); }
const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const rand = (n = 24) => b64u(crypto.getRandomValues(new Uint8Array(n)));

export const validDomain = (d) => typeof d === "string" && d.length <= 253 && /^(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$/.test(d) && !/^\d+(\.\d+)+$/.test(d);
const validEmail = (e) => typeof e === "string" && e.length <= 254 && /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]{2,}$/.test(e);
const clean = (s, max) => String(s ?? "").replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, max);

async function body(req) {
  const t = await req.text();
  if (t.length > 4096) throw new HttpError(413, "Too large");
  try { return JSON.parse(t || "{}"); } catch { throw new HttpError(400, "Bad JSON"); }
}
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

// Count an event; throw 429 when over the limit.
async function limit(db, key, max, windowMs, now) {
  const w = Math.floor(now / windowMs) * windowMs;
  await db.prepare("INSERT INTO limits (k, w, n) VALUES (?, ?, 1) ON CONFLICT(k, w) DO UPDATE SET n = n + 1").bind(key, w).run();
  const row = await db.prepare("SELECT n FROM limits WHERE k = ? AND w = ?").bind(key, w).first();
  if (row.n > max) throw new HttpError(429, "Too many requests. Try again later.");
}

async function auth(req, env) {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer ([A-Za-z0-9_-]{8,64})\.([A-Za-z0-9_-]{16,80})$/.exec(h);
  if (!m) throw new HttpError(401, "Not signed in");
  const row = await env.DB.prepare("SELECT id, key_hash FROM installs WHERE id = ?").bind(m[1]).first();
  if (!row || row.key_hash !== (await sha256(m[2]))) throw new HttpError(401, "Not signed in");
  return row.id;
}

export async function handle(req, env, deps = {}) {
  const now = (deps.now || Date.now)();
  const mail = deps.mail || (async (to, subject, text) => sendResend(env, to, subject, text));
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  try {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, POST, DELETE, OPTIONS", "access-control-max-age": "86400" } });

    // ---- install: get an id + secret key. The key is shown once and only its hash is stored. ----
    if (req.method === "POST" && path === "/v1/install") {
      const ip = req.headers.get("cf-connecting-ip") || "0";
      const ipHash = await sha256(env.SALT + ip);
      await limit(env.DB, "install:" + ipHash, 10, DAY, now);
      const id = rand(9), key = rand(24);
      await env.DB.prepare("INSERT INTO installs (id, key_hash, ip_hash, created_at) VALUES (?, ?, ?, ?)").bind(id, await sha256(key), ipHash, now).run();
      return json({ id, key }, 201);
    }

    // ---- shared warning list ----
    if (req.method === "GET" && path === "/v1/list") {
      const rows = (await env.DB.prepare("SELECT domain, findings, confirmations FROM listed ORDER BY listed_at DESC LIMIT 5000").all()).results;
      return json({ updated: now, minConfirmations: MIN_CONFIRMATIONS, domains: rows.map((r) => ({ d: r.domain, f: r.findings.split(","), n: r.confirmations })) }, 200, { "cache-control": "public, max-age=1800" });
    }

    if (req.method === "POST" && path === "/v1/reports") {
      const id = await auth(req, env);
      const b = await body(req);
      const domain = clean(b.domain, 253).toLowerCase();
      if (!validDomain(domain)) throw new HttpError(400, "Bad domain");
      if (!FINDINGS.has(b.finding)) throw new HttpError(400, "Bad finding");
      await limit(env.DB, "report:" + id, 20, DAY, now);
      await env.DB.prepare("INSERT OR IGNORE INTO reports (install_id, domain, finding, created_at) VALUES (?, ?, ?, ?)").bind(id, domain, b.finding, now).run();
      const listed = await promote(env.DB, domain, now);
      return json({ ok: true, listed });
    }

    // ---- trusted people ----
    if (path === "/v1/guardians" && req.method === "GET") {
      const id = await auth(req, env);
      const rows = (await env.DB.prepare("SELECT id, name, status, created_at FROM guardians WHERE install_id = ? AND status IN ('pending','active') ORDER BY created_at").bind(id).all()).results;
      return json({ guardians: rows });
    }

    if (path === "/v1/guardians" && req.method === "POST") {
      const id = await auth(req, env);
      const b = await body(req);
      const email = clean(b.email, 254).toLowerCase(), name = clean(b.name, 60), requester = clean(b.yourName, 60);
      if (!validEmail(email)) throw new HttpError(400, "That email doesn't look right");
      if (!name || !requester) throw new HttpError(400, "Add both names");
      const emailHash = await sha256(email);
      if (await env.DB.prepare("SELECT 1 AS x FROM blocked_emails WHERE email_hash = ?").bind(emailHash).first()) throw new HttpError(403, "This person asked not to be invited.");
      const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM guardians WHERE install_id = ? AND status IN ('pending','active')").bind(id).first();
      if (count.n >= MAX_GUARDIANS) throw new HttpError(409, `You can have up to ${MAX_GUARDIANS} trusted people`);
      await limit(env.DB, "invite:" + id, 5, DAY, now);
      await limit(env.DB, "invite-email:" + emailHash, 2, DAY, now); // nobody can be spammed with invites
      const gid = rand(9), token = rand(24);
      await env.DB.prepare("INSERT INTO guardians (id, install_id, email, name, requester, status, token_hash, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)").bind(gid, id, email, name, requester, await sha256(token), now).run();
      const base = env.PUBLIC_URL.replace(/\/+$/, "");
      await mail(email, `${requester} would like you as a trusted person on Decoy`,
        `Hi ${name},\n\n${requester} uses Decoy, a browser tool that warns about scam websites. They'd like you to be a trusted person: if they land on a very risky page, you'd get a short email so you can check in with them.\n\n` +
        `What you'd get: the scam site's address, the time, and whether ${requester} typed anything into it.\nWhat you would NOT get: what they typed, the pages they visit, or any browsing history.\n\n` +
        `Yes, I'll be their trusted person:\n${base}/v1/confirm?t=${token}&a=yes\n\nNo thanks (and please don't ask me again):\n${base}/v1/confirm?t=${token}&a=no\n\nIf you do nothing, nothing happens. ${requester} can remove you any time, and so can you using the link in any alert.\n`);
      return json({ ok: true, id: gid }, 201);
    }

    const del = /^\/v1\/guardians\/([A-Za-z0-9_-]{8,24})$/.exec(path);
    if (del && req.method === "DELETE") {
      const id = await auth(req, env);
      const r = await env.DB.prepare("UPDATE guardians SET status = 'removed', email = '' WHERE id = ? AND install_id = ? AND status IN ('pending','active')").bind(del[1], id).run();
      return r.meta?.changes ? json({ ok: true }) : err(404, "Not found");
    }

    if (req.method === "GET" && path === "/v1/confirm") {
      const t = url.searchParams.get("t") || "", a = url.searchParams.get("a");
      const g = /^[A-Za-z0-9_-]{16,64}$/.test(t) ? await env.DB.prepare("SELECT * FROM guardians WHERE token_hash = ?").bind(await sha256(t)).first() : null;
      if (!g || g.status === "removed") return html("<h2>This link isn't valid anymore.</h2>", 404);
      if (a === "no") {
        await env.DB.prepare("INSERT OR IGNORE INTO blocked_emails (email_hash, created_at) VALUES (?, ?)").bind(await sha256(g.email), now).run();
        await env.DB.prepare("UPDATE guardians SET status = 'declined', email = '' WHERE id = ?").bind(g.id).run();
        return html("<h2>Done. You won't be asked again.</h2><p>Nothing was shared and you won't get any emails from Decoy.</p>");
      }
      if (g.status === "pending") await env.DB.prepare("UPDATE guardians SET status = 'active', confirmed_at = ? WHERE id = ?").bind(now, g.id).run();
      return html(`<h2>You're now ${esc(g.requester)}'s trusted person.</h2><p>If they land on a very risky scam page, you'll get a short email. You'll never see what they type or what they browse.</p><p><a href="${esc(env.PUBLIC_URL.replace(/\/+$/, ""))}/v1/confirm?t=${esc(t)}&a=no">Stop being their trusted person</a></p>`);
    }

    // ---- alerts: Decoy tells your trusted people about a very risky moment ----
    if (req.method === "POST" && path === "/v1/alerts") {
      const id = await auth(req, env);
      const b = await body(req);
      const domain = clean(b.domain, 253).toLowerCase();
      if (!validDomain(domain)) throw new HttpError(400, "Bad domain");
      if (!ALERT_KINDS.has(b.kind)) throw new HttpError(400, "Bad kind");
      const entered = b.entered ? 1 : 0;
      await limit(env.DB, "alert-day:" + id, 10, DAY, now);
      const recent = await env.DB.prepare("SELECT 1 AS x FROM alerts WHERE install_id = ? AND domain = ? AND created_at > ? AND entered >= ?").bind(id, domain, now - HOUR, entered).first();
      if (recent) return json({ ok: true, sent: 0, skipped: "recent" });
      await env.DB.prepare("INSERT INTO alerts (id, install_id, kind, domain, entered, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(rand(9), id, b.kind, domain, entered, now).run();
      const gs = (await env.DB.prepare("SELECT id, email, name, requester FROM guardians WHERE install_id = ? AND status = 'active'").bind(id).all()).results;
      let sent = 0;
      for (const g of gs) {
        const what = { likely: "a page that looks like a scam", grabber: "a site that grabbed the details typed into it", download: "a dangerous download", entered: "a scam page" }[b.kind];
        await mail(g.email, `${g.requester} may need a hand: scam warning`,
          `Hi ${g.name},\n\nDecoy warned ${g.requester} about ${what}.\n\nSite: ${domain}\nTime: ${new Date(now).toUTCString()}\n${entered ? `${g.requester} DID type details into it. A quick call now could help: change the password, tell the bank.` : `${g.requester} did not type anything into it.`}\n\nThis email does not include what they typed or what else they browse.\nTo stop getting these: ${env.PUBLIC_URL.replace(/\/+$/, "")} (use the link in your first invite) or ask ${g.requester} to remove you.\n`);
        sent++;
      }
      return json({ ok: true, sent });
    }

    if (path === "/" && req.method === "GET") return json({ name: "decoy-cloud", ok: true });
    return err(404, "Not found");
  } catch (e) {
    if (e instanceof HttpError) return err(e.status, e.message);
    return err(500, "Something went wrong");
  }
}

// A domain goes on the shared list once enough different people, from different networks, confirmed it.
async function promote(db, domain, now) {
  const placeholders = [...FINDINGS].map(() => "?").join(",");
  const rows = (await db.prepare(`SELECT r.finding, i.ip_hash FROM reports r JOIN installs i ON i.id = r.install_id WHERE r.domain = ? AND r.finding IN (${placeholders}) AND i.created_at < ?`).bind(domain, ...FINDINGS, now - HOUR).all()).results;
  const sources = new Set(rows.map((r) => r.ip_hash));
  if (sources.size < MIN_CONFIRMATIONS) return false;
  const findings = [...new Set(rows.map((r) => r.finding))].sort().join(",");
  await db.prepare("INSERT INTO listed (domain, findings, confirmations, listed_at) VALUES (?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET findings = excluded.findings, confirmations = excluded.confirmations").bind(domain, findings, sources.size, now).run();
  return true;
}

async function sendResend(env, to, subject, text) {
  if (!env.RESEND_API_KEY) throw new Error("mail not configured");
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM, to, subject, text }) });
  if (!r.ok) throw new Error("mail failed");
}
