import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { md5 } from "../src/md5.js";
import { matchNeedles } from "../src/match.js";
import { makeCanary, buildNeedles } from "../src/canary.js";
import { classify } from "../src/destinations.js";
import { judgeFinding, buildVerdict } from "../src/verdict.js";

// ---- md5 / canary / matcher ----
test("md5 matches Node's crypto for many inputs (incl. block boundaries)", () => {
  for (const s of ["", "a", "abc", "dc-k7x2qp@example.com", "x".repeat(55), "x".repeat(56), "x".repeat(64), "é日本語", "y".repeat(1000)])
    assert.equal(md5(s), createHash("md5").update(s).digest("hex"), JSON.stringify(s.slice(0, 20)));
});

test("canary needles are found in plain, url, base64, hex and hashed shapes", async () => {
  const id = makeCanary();
  const needles = await buildNeedles(id);
  const sha = createHash("sha256").update(id.email).digest("hex");
  const sha1 = createHash("sha1").update(id.email).digest("hex");
  const cases = {
    plain: `email=${id.email}`,
    url: `https://x.test/?e=${encodeURIComponent(id.email)}`,
    formenc: new URLSearchParams({ p: id.password }).toString(),
    json: JSON.stringify({ user: { password: id.password } }),
    base64: `d=${Buffer.from(id.password).toString("base64")}`,
    hex: Buffer.from(id.email).toString("hex"),
    sha256: `ud[em]=${sha}`,
    SHA256UPPER: `ud=${sha.toUpperCase()}`,
    sha1: `h=${sha1}`,
    md5: `h=${md5(id.email)}`,
    phone: `tel=${id.phone}`,
    card: "n=4242 4242 4242 4242",
  };
  for (const [name, hay] of Object.entries(cases)) assert.ok(matchNeedles(hay, needles).length, `${name} not found in ${hay}`);
  assert.equal(matchNeedles("nothing to see here, user@other.com 12345", needles).length, 0);
});

test("canary identities are unique each time", () => {
  const a = makeCanary(), b = makeCanary();
  assert.notEqual(a.email, b.email);
  assert.notEqual(a.password, b.password);
});

// ---- destinations ----
const PAGE = "shop.example.com";
const k = (u) => classify(u, PAGE).kind;
test("classify: first party, providers, analytics, form services", () => {
  assert.equal(k("https://shop.example.com/api/x"), "first");
  assert.equal(k("https://cdn.example.com/x"), "first");
  assert.equal(k("https://api.stripe.com/v1/tokens"), "provider");
  assert.equal(k("https://www.facebook.com/tr?ud=1"), "analytics");
  assert.equal(k("https://formspree.io/f/abc"), "formsvc");
  assert.equal(k("https://docs.google.com/forms/d/e/1/formResponse"), "formsvc");
  assert.equal(k("https://www.google.com/recaptcha/api2"), "provider");
});
test("classify: grabbers and suspicious hosts", () => {
  assert.equal(k("https://api.telegram.org/bot123:ABC/sendMessage?x=1"), "grabber");
  assert.equal(k("https://api.telegram.org/somethingelse"), "unknown");
  assert.equal(k("https://discord.com/api/webhooks/1/abc"), "grabber");
  assert.equal(k("https://discordapp.com/api/webhooks/1/abc"), "grabber");
  assert.equal(k("https://pastebin.com/api/api_post.php"), "grabber");
  assert.equal(k("https://abc123.ngrok-free.app/p"), "grabber");
  assert.equal(k("http://45.9.148.20/gate.php"), "grabber");
  assert.equal(k("https://hooks.slack.com/services/T/B/x"), "grabber");
  assert.equal(k("https://thing.workers.dev/in"), "suspicious");
  assert.equal(k("https://random-collector.test/p.php"), "unknown");
});

// ---- judging ----
const hit = (url, kinds, extra = {}) => ({ url, via: "fetch", hits: kinds.map((kind) => ({ kind, enc: "plain" })), beforeSubmit: false, ...extra });
const sev = (url, kinds, extra) => judgeFinding(hit(url, kinds, extra), PAGE).severity;

test("judge: normal flows are OK or info", () => {
  assert.equal(sev("https://shop.example.com/api/signup", ["email", "password"]), "ok");
  assert.equal(sev("https://api.stripe.com/v1/tokens", ["card"]), "ok");
  assert.equal(sev("https://www.facebook.com/tr?ud=x", ["email"], { hits: [{ kind: "email", enc: "sha256" }], beforeSubmit: true }), "info");
  assert.equal(sev("https://formspree.io/f/abc", ["email"]), "info");
});
test("judge: unknown third party", () => {
  assert.equal(sev("https://other-site.test/collect", ["email"]), "warn");
  assert.equal(sev("https://other-site.test/collect", ["password"]), "strong");
  assert.equal(sev("https://other-site.test/collect", ["email"], { beforeSubmit: true }), "strong");
});
test("judge: grabbers, analytics+password, plain http", () => {
  assert.equal(sev("https://api.telegram.org/bot1:A/sendMessage", ["email"]), "strong");
  assert.equal(sev("https://www.facebook.com/tr", ["password"]), "strong");
  assert.equal(sev("http://shop.example.com/login", ["password"]), "strong");
});
test("judge: text says what happened", () => {
  const f = judgeFinding(hit("https://api.telegram.org/bot1:A/x", ["password"], { beforeSubmit: true }), PAGE);
  assert.match(f.text, /Password sent to api\.telegram\.org \(a Telegram bot\), before you pressed submit/);
});

// ---- verdict ----
const base = { host: PAGE, submitted: true, hadPassword: true, findings: [], pages: [] };
test("verdict: waiting before anything happens", () => {
  assert.equal(buildVerdict({ ...base, submitted: false }).status, "waiting");
});
test("verdict: clean when data only went to the site + provider", () => {
  const v = buildVerdict({ ...base, findings: [hit("https://shop.example.com/a", ["email"]), hit("https://api.stripe.com/t", ["card"])] });
  assert.equal(v.status, "clean");
  assert.match(v.sub, /this site/);
});
test("verdict: analytics hashing alone stays clean", () => {
  const v = buildVerdict({ ...base, findings: [hit("https://shop.example.com/a", ["email"]), hit("https://www.facebook.com/tr", ["email"], { hits: [{ kind: "email", enc: "sha256" }] })] });
  assert.equal(v.status, "clean");
});
test("verdict: one unknown recipient -> careful; plus a bad page score -> grabber", () => {
  const f = [hit("https://other-site.test/c", ["email"])];
  assert.equal(buildVerdict({ ...base, findings: f }).status, "careful");
  assert.equal(buildVerdict({ ...base, findings: f }, { pageScore: 80 }).status, "grabber");
});
test("verdict: redirect to the real brand after submit is strong", () => {
  const v = buildVerdict({ ...base, pages: [{ host: "www.paypal.com", afterSubmit: true }] });
  assert.equal(v.status, "grabber");
  assert.match(v.items[0].text, /real paypal site/);
});
test("verdict: landing on a brand BEFORE submitting is not a redirect finding", () => {
  const v = buildVerdict({ ...base, submitted: false, pages: [{ host: "www.paypal.com", afterSubmit: false }] });
  assert.equal(v.status, "waiting");
});
test("verdict: login then 'enter your card + OTP' -> warn", () => {
  const v = buildVerdict({ ...base, pages: [{ host: PAGE, afterSubmit: true, extraAsk: ["card details", "a one-time code"] }] });
  assert.equal(v.status, "careful");
  assert.match(v.items[0].text, /card details and a one-time code/);
});
test("verdict: always carries the honest limit", () => {
  assert.match(buildVerdict(base).limit, /pass your data on from its own servers/);
});

test("verdict: many values to one destination become one line", () => {
  const f = ["email", "password", "phone", "card"].map((k) => hit("https://api.telegram.org/bot1:A/sendMessage", [k], { beforeSubmit: true }));
  const v = buildVerdict({ ...base, submitted: false, findings: f });
  assert.equal(v.items.length, 1);
  assert.match(v.items[0].text, /^Email, password, phone number and card number sent to api\.telegram\.org/);
});
test("verdict: harmless pixels don't get a scary 'before you pressed submit'", () => {
  const f = judgeFinding(hit("https://www.facebook.com/tr", ["email"], { beforeSubmit: true, hits: [{ kind: "email", enc: "sha256" }] }), PAGE);
  assert.equal(f.severity, "info");
  assert.ok(!/before you pressed submit/.test(f.text));
});

test("classify: plain http to your own machine is not 'unencrypted'", () => {
  assert.equal(classify("http://collector.localhost:8080/p", "grabber.localhost").insecure, false);
  assert.equal(classify("http://127.0.0.1:3000/p", "app.localhost").insecure, false);
  assert.equal(classify("http://203.0.113.9/p", "shop.example.com").insecure, true);
});
