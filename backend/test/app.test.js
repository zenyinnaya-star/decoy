import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handle, MIN_CONFIRMATIONS } from "../src/app.js";

// A tiny stand-in for Cloudflare D1, backed by Node's built-in SQLite.
function d1() {
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(new URL("../migrations/0001_init.sql", import.meta.url), "utf8"));
  // Like D1: prepare(sql) can be run/first/all directly, or bind(...) first.
  const stmt = (sql, a = []) => ({
    bind: (...b) => stmt(sql, b),
    run: async () => ({ meta: { changes: db.prepare(sql).run(...a).changes } }),
    first: async () => db.prepare(sql).get(...a) ?? null,
    all: async () => ({ results: db.prepare(sql).all(...a) }),
  });
  return { prepare: (sql) => stmt(sql) };
}

function world() {
  const env = { DB: d1(), SALT: "s", PUBLIC_URL: "https://x.test", MAIL_FROM: "a@b.c" };
  const mails = []; let t = 1_000_000_000_000;
  const deps = { mail: async (to, subject, text) => mails.push({ to, subject, text }), now: () => t };
  const call = async (method, path, { body, auth, ip = "1.1.1.1" } = {}) => {
    const r = await handle(new Request("https://x.test" + path, { method, body: body ? JSON.stringify(body) : undefined, headers: { "cf-connecting-ip": ip, ...(auth ? { authorization: `Bearer ${auth.id}.${auth.key}` } : {}) } }), env, deps);
    const text = await r.text(); let j = null; try { j = JSON.parse(text); } catch {}
    return { status: r.status, j, text };
  };
  const install = async (ip) => (await call("POST", "/v1/install", { ip })).j;
  return { env, mails, call, install, advance: (ms) => { t += ms; } };
}
const token = (mail, a = "yes") => new RegExp(`t=([A-Za-z0-9_-]+)&a=${a}`).exec(mail.text)[1];

test("install gives an id and key; calls without them are refused", async () => {
  const w = world();
  const me = await w.install();
  assert.ok(me.id && me.key);
  assert.equal((await w.call("POST", "/v1/reports", { body: { domain: "evil.example", finding: "grabber-endpoint" } })).status, 401);
  assert.equal((await w.call("POST", "/v1/reports", { auth: { id: me.id, key: "wrongwrongwrongwrong" }, body: { domain: "evil.example", finding: "grabber-endpoint" } })).status, 401);
});

test("install is rate limited per network", async () => {
  const w = world();
  for (let i = 0; i < 10; i++) assert.equal((await w.call("POST", "/v1/install")).status, 201);
  assert.equal((await w.call("POST", "/v1/install")).status, 429);
});

test("reports: bad input is refused", async () => {
  const w = world(); const me = await w.install();
  for (const body of [{ domain: "nodot", finding: "grabber-endpoint" }, { domain: "1.2.3.4", finding: "grabber-endpoint" }, { domain: "evil.example", finding: "made-up" }, { domain: "-bad.example", finding: "keystroke-leak" }]) {
    assert.equal((await w.call("POST", "/v1/reports", { auth: me, body })).status, 400, JSON.stringify(body));
  }
});

test("a site is listed only after enough DIFFERENT people on DIFFERENT networks confirm it", async () => {
  const w = world();
  const people = [];
  for (let i = 0; i < MIN_CONFIRMATIONS; i++) people.push(await w.install(`9.9.9.${i}`));
  w.advance(2 * 3600_000); // installs must be a little older than the report
  const rep = (p) => w.call("POST", "/v1/reports", { auth: p, body: { domain: "paypa1-login.example", finding: "password-third-party" } });
  assert.equal((await rep(people[0])).j.listed, false);
  assert.equal((await rep(people[0])).j.listed, false); // the same person twice still counts once
  assert.equal((await rep(people[1])).j.listed, false);
  assert.equal((await rep(people[2])).j.listed, true);
  const list = await w.call("GET", "/v1/list");
  assert.deepEqual(list.j.domains.map((d) => d.d), ["paypa1-login.example"]);
  assert.equal(list.j.domains[0].n, MIN_CONFIRMATIONS);
});

test("one person with many installs from one network cannot list a site", async () => {
  const w = world();
  const bots = []; for (let i = 0; i < 6; i++) bots.push(await w.install("7.7.7.7"));
  w.advance(2 * 3600_000);
  for (const b of bots) await w.call("POST", "/v1/reports", { auth: b, body: { domain: "rival-shop.example", finding: "grabber-endpoint" } });
  assert.equal((await w.call("GET", "/v1/list")).j.domains.length, 0);
});

test("brand-new installs do not count toward listing", async () => {
  const w = world();
  const people = []; for (let i = 0; i < 3; i++) people.push(await w.install(`8.8.8.${i}`));
  for (const p of people) await w.call("POST", "/v1/reports", { auth: p, body: { domain: "fresh-bots.example", finding: "keystroke-leak" } });
  assert.equal((await w.call("GET", "/v1/list")).j.domains.length, 0);
});

test("reports are limited to 20 a day per install", async () => {
  const w = world(); const me = await w.install();
  let last;
  for (let i = 0; i < 21; i++) last = await w.call("POST", "/v1/reports", { auth: me, body: { domain: `s${i}.example`, finding: "skim-read" } });
  assert.equal(last.status, 429);
});

test("trusted person flow: invite, nothing sent until they say yes, then alerts, then removal", async () => {
  const w = world(); const me = await w.install();
  const inv = await w.call("POST", "/v1/guardians", { auth: me, body: { email: "Sam@Example.com", name: "Sam", yourName: "Alex" } });
  assert.equal(inv.status, 201);
  assert.equal(w.mails.length, 1);
  assert.equal(w.mails[0].to, "sam@example.com");
  assert.match(w.mails[0].text, /would NOT get: what they typed/);

  // pending: an alert goes nowhere
  let a = await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "likely", domain: "scam.example", entered: false } });
  assert.equal(a.j.sent, 0);
  assert.equal(w.mails.length, 1);

  // Sam says yes
  const yes = await w.call("GET", `/v1/confirm?t=${token(w.mails[0])}&a=yes`);
  assert.equal(yes.status, 200); assert.match(yes.text, /trusted person/);
  assert.equal((await w.call("GET", "/v1/guardians", { auth: me })).j.guardians[0].status, "active");

  w.advance(2 * 3600_000);
  a = await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "entered", domain: "scam.example", entered: true } });
  assert.equal(a.j.sent, 1);
  const alert = w.mails[1];
  assert.equal(alert.to, "sam@example.com");
  assert.match(alert.text, /scam\.example/); assert.match(alert.text, /DID type details/);
  assert.doesNotMatch(alert.text, /card number|typed:/i);

  // Alex removes Sam: no more alerts, and the stored email is wiped
  const id = (await w.call("GET", "/v1/guardians", { auth: me })).j.guardians[0].id;
  assert.equal((await w.call("DELETE", `/v1/guardians/${id}`, { auth: me })).status, 200);
  w.advance(2 * 3600_000);
  a = await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "likely", domain: "other.example", entered: false } });
  assert.equal(a.j.sent, 0);
  assert.equal((await w.env.DB.prepare("SELECT email FROM guardians WHERE id = ?").bind(id).first()).email, "");
});

test("'No thanks' blocks that email for good and sends nothing", async () => {
  const w = world(); const me = await w.install(); const other = await w.install("2.2.2.2");
  await w.call("POST", "/v1/guardians", { auth: me, body: { email: "nope@example.com", name: "N", yourName: "A" } });
  const no = await w.call("GET", `/v1/confirm?t=${token(w.mails[0], "no")}&a=no`);
  assert.match(no.text, /won't be asked again/);
  const again = await w.call("POST", "/v1/guardians", { auth: other, body: { email: "NOPE@example.com", name: "N", yourName: "B" } });
  assert.equal(again.status, 403);
  assert.equal(w.mails.length, 1);
});

test("limits: 3 trusted people, and one email can't be spammed with invites", async () => {
  const w = world(); const me = await w.install();
  for (const e of ["a@x.com", "b@x.com", "c@x.com"]) assert.equal((await w.call("POST", "/v1/guardians", { auth: me, body: { email: e, name: "N", yourName: "A" } })).status, 201);
  assert.equal((await w.call("POST", "/v1/guardians", { auth: me, body: { email: "d@x.com", name: "N", yourName: "A" } })).status, 409);

  const w2 = world(); const ps = []; for (let i = 0; i < 4; i++) ps.push(await w2.install(`3.3.3.${i}`));
  const r = []; for (const p of ps) r.push((await w2.call("POST", "/v1/guardians", { auth: p, body: { email: "victim@x.com", name: "V", yourName: "A" } })).status);
  assert.deepEqual(r, [201, 201, 429, 429]);
});

test("alerts: duplicates within an hour are skipped, bad input refused", async () => {
  const w = world(); const me = await w.install();
  await w.call("POST", "/v1/guardians", { auth: me, body: { email: "s@x.com", name: "S", yourName: "A" } });
  await w.call("GET", `/v1/confirm?t=${token(w.mails[0])}&a=yes`);
  const send = () => w.call("POST", "/v1/alerts", { auth: me, body: { kind: "likely", domain: "scam.example", entered: false } });
  assert.equal((await send()).j.sent, 1);
  assert.equal((await send()).j.skipped, "recent");
  // but if they then typed something, that is news worth a second email
  assert.equal((await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "entered", domain: "scam.example", entered: true } })).j.sent, 1);
  assert.equal((await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "nope", domain: "scam.example" } })).status, 400);
  assert.equal((await w.call("POST", "/v1/alerts", { auth: me, body: { kind: "likely", domain: "not a domain" } })).status, 400);
});

test("confirm links: garbage is refused, names can't inject markup", async () => {
  const w = world(); const me = await w.install();
  assert.equal((await w.call("GET", "/v1/confirm?t=garbage&a=yes")).status, 404);
  await w.call("POST", "/v1/guardians", { auth: me, body: { email: "s@x.com", name: "S", yourName: "<script>alert(1)</script>Al" } });
  const page = await w.call("GET", `/v1/confirm?t=${token(w.mails[0])}&a=yes`);
  assert.doesNotMatch(page.text, /<script>/);
});

test("oversized or malformed bodies are refused, unknown paths 404", async () => {
  const w = world(); const me = await w.install();
  assert.equal((await w.call("POST", "/v1/reports", { auth: me, body: { domain: "a".repeat(5000) + ".example", finding: "skim-read" } })).status, 413);
  assert.equal((await w.call("GET", "/v1/nothing")).status, 404);
});
