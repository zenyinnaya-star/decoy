// Runs the REAL testbed server and drives Chromium + the built extension against it.
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const http = require("node:http");
const assert = require("node:assert/strict");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");
const PORT = 18080;
const at = (n, p = "/") => `http://${n}.localhost:${PORT}${p}`;

const collectorLog = () => new Promise((resolve, reject) => {
  http.get({ host: "127.0.0.1", port: PORT, path: "/log", headers: { host: `collector.localhost:${PORT}` } }, (r) => {
    let b = ""; r.on("data", (d) => (b += d)); r.on("end", () => resolve(b));
  }).on("error", reject);
});

(async () => {
  const { computeScore } = await import(path.resolve(__dirname, "../../src/score.js"));
  const server = spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "inherit", "inherit"], cwd: path.resolve(__dirname, "../..") });
  await new Promise((r) => setTimeout(r, 700));

  const ctx = await chromium.launchPersistentContext("", {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);

  const newestTab = () => popup.evaluate(async () => Math.max(...(await chrome.tabs.query({})).map((t) => t.id)));
  const toTab = (t, m) => popup.evaluate(([t, m]) => chrome.tabs.sendMessage(t, m, { frameId: 0 }), [t, m]);
  const ask = (t, m) => popup.evaluate(([t, m]) => chrome.runtime.sendMessage({ ...m, tabId: t }), [t, m]);

  async function open(url) {
    const page = await ctx.newPage();
    await page.goto(url);
    await page.waitForTimeout(500);
    return { page, tab: await newestTab() };
  }
  async function scan(url) {
    const { page, tab } = await open(url);
    const s = await toTab(tab, { type: "scan" });
    const a = await ask(tab, { type: "assess", scan: s });
    const r = computeScore(a.flags, { trustKind: a.trustKind });
    console.log(`   ${r.level} (${r.score}${r.capped ? ", capped: " + r.capped : ""}): ${r.flags.map((f) => `${f.tier === "strong" ? "!" : ""}${f.id}`).join(", ") || "-"}`);
    await page.close();
    return r;
  }
  async function dummy(url, { wait = 1200 } = {}) {
    const { page, tab } = await open(url);
    await toTab(tab, { type: "dummy:start" });
    await page.click("form button, form input[type=submit]");
    await page.waitForTimeout(wait);
    const st = await ask(tab, { type: "dummy:state" });
    console.log(`   ${st.verdict.title} | ${st.verdict.items.map((i) => `[${i.severity}] ${i.text}`).join(" | ") || st.verdict.sub}`);
    await page.close();
    return st.verdict;
  }

  let failed = 0;
  const check = (label, fn) => { try { fn(); console.log(`   ok   ${label}`); } catch (e) { failed++; console.log(`   FAIL ${label}: ${e.message.split("\n")[0]}`); } };

  console.log("\n== SCAN: paypal-secure-login");
  let r = await scan(at("paypal-secure-login"));
  check("Likely scam", () => assert.equal(r.level, "Likely scam"));

  console.log("\n== SCAN: arnazon-signin");
  r = await scan(at("arnazon-signin"));
  check("Likely scam", () => assert.equal(r.level, "Likely scam"));

  console.log("\n== SCAN: nike-outlet-sale");
  r = await scan(at("nike-outlet-sale"));
  check("Sketchy: fake-shop pattern (card form + 3 shop warning signs)", () => { assert.equal(r.level, "Sketchy"); assert.ok(r.flags.some((f) => f.id === "fakeshop")); });

  for (const n of ["honest-shop", "quiet-shop", "tracker-shop", "grabber"]) {
    console.log(`\n== SCAN: ${n}`);
    r = await scan(at(n));
    check(n === "grabber" ? "Looks fine on sight (that's the point: only the dummy test catches it)" : "Looks fine", () => assert.equal(r.level, "Looks fine"));
  }

  console.log("\n== DUMMY: grabber");
  let v = await dummy(at("grabber"), { wait: 1800 });
  check("data grabber", () => assert.equal(v.status, "grabber"));
  check("keystroke exfil before submit", () => assert.ok(v.items.some((i) => i.severity === "strong" && /collector\.localhost/.test(i.text) && /before you pressed submit/.test(i.text))));
  check("bounce to the brand", () => assert.ok(v.items.some((i) => /real paypal site/.test(i.text))));
  check("follow-up one-time-code ask", () => assert.ok(v.items.some((i) => /one-time code/.test(i.text))));

  console.log("\n== DUMMY: paypal-secure-login (native form POST to another site)");
  v = await dummy(at("paypal-secure-login"));
  check("data grabber", () => assert.equal(v.status, "grabber"));
  check("password sent to collector", () => assert.ok(v.items.some((i) => i.severity === "strong" && /password/i.test(i.text) && /collector\.localhost/.test(i.text))));

  console.log("\n== DUMMY: tracker-shop");
  v = await dummy(at("tracker-shop"));
  check("No leak seen", () => assert.equal(v.status, "clean"));
  check("pixel shown as info", () => assert.ok(v.items.some((i) => i.severity === "info" && /facebook\.com/.test(i.text))));

  for (const n of ["honest-shop", "quiet-shop"]) {
    console.log(`\n== DUMMY: ${n}`);
    v = await dummy(at(n));
    check("No leak seen", () => assert.equal(v.status, "clean"));
  }

  console.log("\n== GROUND TRUTH: what the pretend attacker's collector received");
  const log = await collectorLog();
  check("collector got the stolen password (Dc- canary)", () => assert.match(log, /Dc-/));
  check("collector got keystroke messages", () => assert.match(log, /sendMessage/));
  check("collector got the POSTed credentials", () => assert.match(log, /p\.php/));

  console.log(failed ? `\n${failed} FAILED` : "\nALL TESTBED CHECKS PASSED");
  await ctx.close(); server.kill();
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
