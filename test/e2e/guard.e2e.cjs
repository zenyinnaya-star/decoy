// Phase D guards, driven in real Chromium against the real testbed.
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");
const PORT = 18082;
const at = (n) => `http://${n}.localhost:${PORT}/`;
let failed = 0;
const check = (name, fn) => { try { fn(); console.log(`   ok   ${name}`); } catch (e) { failed++; console.log(`   FAIL ${name}: ${e.message.split("\n")[0]}`); } };

(async () => {
  const server = spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "inherit", "inherit"], cwd: path.resolve(__dirname, "../..") });
  await new Promise((r) => setTimeout(r, 700));
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"]);
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  const newestTab = () => popup.evaluate(async () => Math.max(...(await chrome.tabs.query({})).map((t) => t.id)));
  const guards = async (tab) => (await popup.evaluate((t) => chrome.runtime.sendMessage({ type: "guard:state", tabId: t }), tab)).map((g) => g.id);

  async function visit(name, act, prompt = false) {
    console.log(`\n== GUARD: ${name}`);
    const page = await ctx.newPage(); let dialogs = 0;
    page.on("dialog", (d) => { dialogs++; d.accept().catch(() => {}); });
    if (prompt) { // headless Chromium reports every permission as "denied"; make them "prompt" like a real browser
      const cdp = await ctx.newCDPSession(page);
      for (const n of ["geolocation", "notifications", "camera"]) await cdp.send("Browser.setPermission", { origin: at(name).replace(/\/$/, ""), permission: { name: n }, setting: "prompt" });
    }
    await page.goto(at(name)); const tab = await newestTab();
    if (act) await act(page);
    await page.waitForTimeout(1500);
    const kinds = await guards(tab); const out = (await page.textContent("#out").catch(() => "")) || "";
    console.log(`   kinds=[${kinds}] out="${out.trim()}" dialogs=${dialogs}`);
    await page.close(); return { kinds, out, dialogs };
  }

  let r = await visit("fake-captcha", (p) => p.click("#b"));
  check("ClickFix command blocked", () => assert.ok(r.kinds.includes("clipboard-command")));
  r = await visit("docs-install", (p) => p.click("#b"));
  check("docs Copy button left alone", () => assert.deepEqual(r.kinds, []));
  check("docs copy actually worked", () => assert.equal(r.out.trim(), "copied"));
  r = await visit("clipboard-swap");
  check("silent crypto-address write caught", () => assert.ok(r.kinds.includes("clipboard-crypto")));
  r = await visit("permission-spam", null, true);
  check("permission asks held back and reported", () => assert.ok(r.kinds.includes("perm-prompt")));
  check("repeat asks marked strong", () => assert.ok(r.kinds.includes("perm-repeat")));
  check("none of the three was answered behind your back", () => assert.equal(r.out.trim(), ""));
  r = await visit("store-locator", (p) => p.click("#b"));
  check("location after a click is not interfered with", () => assert.deepEqual(r.kinds, []));
  check("...and the page got an answer", () => assert.match(r.out, /geo:/));
  r = await visit("virus-alert");
  check("alert loop stopped", () => assert.ok(r.kinds.includes("scare-alert")));
  check("only 3 alert boxes reached the screen", () => assert.ok(r.dialogs <= 3, "dialogs=" + r.dialogs));
  check("back-button trap caught", () => assert.ok(r.kinds.includes("scare-history")));
  r = await visit("spa-app", async (p) => { for (let i = 0; i < 3; i++) await p.click("#b"); });
  check("normal SPA left alone", () => assert.deepEqual(r.kinds, []));


  console.log("\n== SAFETY SWITCHES: the escape hatches for when a guard breaks a site");
  const setStore = (o) => popup.evaluate((o) => chrome.storage.local.set(o), o);
  await setStore({ off: { clipboard: true } });
  r = await visit("fake-captcha", (p) => p.click("#b"));
  check("clipboard guard switched off: nothing blocked", () => assert.deepEqual(r.kinds, []));
  check("...and the page's copy really happened", () => assert.equal(r.out.trim(), "copied"));
  await setStore({ off: {} });
  await setStore({ paused: ["virus-alert.localhost", "permission-spam.localhost"] });
  r = await visit("virus-alert");
  check("paused site: alert loop is left alone", () => assert.deepEqual(r.kinds, [], JSON.stringify(r.kinds)));
  check("paused site: all 6 alert boxes reach the screen", () => assert.equal(r.dialogs, 6));
  r = await visit("permission-spam", null, true);
  check("paused site: permission asks pass straight through", () => assert.ok(r.out.trim().length > 0));
  await setStore({ paused: [] });
  r = await visit("virus-alert");
  check("un-paused: guard is back", () => assert.ok(r.kinds.includes("scare-alert")));

  console.log("\n== STEALTH: pages should not be able to tell functions were wrapped");
  {
    const page = await ctx.newPage(); await page.goto(at("honest-shop")); await page.waitForTimeout(500);
    const native = await page.evaluate(() => [window.fetch, XMLHttpRequest.prototype.send, navigator.sendBeacon, Clipboard.prototype.writeText, window.alert, History.prototype.pushState, Function.prototype.toString]
      .map((f) => /\[native code\]/.test(Function.prototype.toString.call(f))));
    check("fetch / XHR / beacon / clipboard / alert / pushState / toString all print as native", () => assert.deepEqual(native, native.map(() => true)));
    await page.close();
  }

  console.log(failed ? `\n${failed} FAILED` : "\nALL GUARD CHECKS PASSED");
  await ctx.close(); server.kill(); process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
