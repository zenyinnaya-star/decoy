// Run the Decoy cloud API on your own machine (in-memory database, mails printed to the console).
//   node backend/dev-server.mjs            -> http://localhost:8787
// DEV=1 adds /__mails and /__advance for tests. Never set DEV in production (this file is not used there anyway).
import fs from "node:fs";
import http from "node:http";
import { DatabaseSync } from "node:sqlite";
import { handle } from "./src/app.js";

const db = new DatabaseSync(":memory:");
for (const f of fs.readdirSync(new URL("./migrations/", import.meta.url)).sort()) db.exec(fs.readFileSync(new URL("./migrations/" + f, import.meta.url), "utf8"));
const stmt = (sql, a = []) => ({
  bind: (...b) => stmt(sql, b),
  run: async () => ({ meta: { changes: db.prepare(sql).run(...a).changes } }),
  first: async () => db.prepare(sql).get(...a) ?? null,
  all: async () => ({ results: db.prepare(sql).all(...a) }),
});
const PORT = Number(process.env.PORT || 8787);
const env = { DB: { prepare: (sql) => stmt(sql) }, SALT: "dev", PUBLIC_URL: `http://localhost:${PORT}`, MAIL_FROM: "dev@localhost" };
const mails = []; let offset = 0;
const deps = { now: () => Date.now() + offset, mail: async (to, subject, text) => { mails.push({ to, subject, text }); console.log(`\n--- mail to ${to}: ${subject}\n${text}`); } };

http.createServer(async (req, res) => {
  const u = new URL(req.url, env.PUBLIC_URL);
  if (process.env.DEV) {
    if (u.pathname === "/__mails") { res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify(mails)); }
    if (u.pathname === "/__advance") { offset += Number(u.searchParams.get("ms") || 0); res.writeHead(200); return res.end("ok"); }
  }
  const chunks = []; for await (const c of req) chunks.push(c);
  const headers = new Headers(); for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
  if (process.env.DEV && req.headers["x-test-ip"]) headers.set("cf-connecting-ip", req.headers["x-test-ip"]);
  else headers.set("cf-connecting-ip", req.socket.remoteAddress || "0");
  const r = await handle(new Request(u, { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks) }), env, deps);
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(PORT, () => console.log(`Decoy cloud (local test copy) on http://localhost:${PORT}`));
