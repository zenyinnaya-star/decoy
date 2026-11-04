// Phase D batch 2 + auto-scan, in real Chromium against the real testbed.
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");
const PORT = 18083;
const at = (n, p = "/") => `http://${n}.localhost:${PORT}${p}`;
let failed = 0;
const check = (name, fn) => { try { fn(); console.log(`   ok   ${name}`); } catch (e) { failed++; console.log(`   FAIL ${name}: ${e.message.split("\n")[0]}`); } };
const acheck = async (name, fn) => { try { await fn(); console.log(`   ok   ${name}`); } catch (e) { failed++; console.log(`   FAIL ${name}: ${e.message.split("\n")[0]}`); } };

(async () => {
  const server = spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "inherit", "inherit"], cwd: path.resolve(__dirname, "../..") });
  await new Promise((r) => setTimeout(r, 700));
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, acceptDownloads: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  const newestTab = () => popup.evaluate(async () => Math.max(...(await chrome.tabs.query({})).map((t) => t.id)));
  const guards = async (tab) => (await popup.evaluate((t) => chrome.runtime.sendMessage({ type: "guard:state", tabId: t }), tab)).map((g) => g.id);
  const badge = (tab) => popup.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tab);
  const setMode = (m) => popup.evaluate((m) => chrome.storage.local.set({ mode: m, muted: [] }), m);
  // The decoy UI lives in a closed shadow root, so ask the browser what is on top at a point.
  const topAt = (page, x, y) => page.evaluate(([x, y]) => document.elementFromPoint(x < 0 ? innerWidth + x : x, y)?.id || "", [x, y]);

  async function visit(url, { wait = 1500, routes = [] } = {}) {
    const page = await ctx.newPage();
    for (const [pat, body] of routes) await page.route(pat, (r) => r.fulfill({ status: 200, contentType: "text/javascript", body }));
    await page.goto(url, { waitUntil: "domcontentloaded" }); const tab = await newestTab();
    await page.waitForTimeout(wait);
    return { page, tab, kinds: await guards(tab) };
  }

  await setMode("auto");

  console.log("\n== AUTO-SCAN: background scan + notice");
  let v = await visit(at("paypal-secure-login"));
  await acheck("badge is !! on a likely scam", async () => assert.equal(await badge(v.tab), "!!"));
  await acheck("look-alike stop screen covers the page (D1)", async () => assert.equal(await topAt(v.page, 100, 300), "decoy-protect-host"));
  await v.page.close();

  v = await visit(at("quiet-shop"));
  await acheck("fine login page: tick badge", async () => assert.equal(await badge(v.tab), "✓"));
  await acheck("brief 'checked' notice appears on a login page", async () => assert.equal(await topAt(v.page, -40, 30), "decoy-protect-host"));
  await v.page.waitForTimeout(4500);
  await acheck("...and goes away by itself", async () => assert.notEqual(await topAt(v.page, -40, 30), "decoy-protect-host"));
  await v.page.close();

  v = await visit(at("spa-app"));
  await acheck("no notice on a normal non-login page", async () => assert.notEqual(await topAt(v.page, -40, 30), "decoy-protect-host"));
  await acheck("...but it still gets a tick badge", async () => assert.equal(await badge(v.tab), "✓"));
  await v.page.close();

  await setMode("ask");
  v = await visit(at("honest-shop"));
  await acheck("ask mode: login page gets a 'scan it?' question", async () => assert.equal(await topAt(v.page, -40, 30), "decoy-protect-host"));
  await acheck("ask mode: nothing scanned until you say so (no badge)", async () => assert.equal(await badge(v.tab), ""));
  await v.page.close();

  await setMode("off");
  v = await visit(at("paypal-secure-login"));
  await acheck("off: no badge", async () => assert.equal(await badge(v.tab), ""));
  await acheck("off: no stop screen", async () => assert.notEqual(await topAt(v.page, 100, 300), "decoy-protect-host"));
  await v.page.close();
  await setMode("auto");

  console.log("\n== D1 look-alike stop screen goes away when you test on purpose");
  v = await visit(at("paypal-secure-login"));
  await popup.evaluate((t) => chrome.tabs.sendMessage(t, { type: "dummy:start" }, { frameId: 0 }), v.tab);
  await v.page.waitForTimeout(600);
  await acheck("testing removes the stop screen", async () => assert.notEqual(await topAt(v.page, 100, 300), "decoy-protect-host"));
  await popup.evaluate((t) => chrome.runtime.sendMessage({ type: "dummy:stop", tabId: t }), v.tab);
  await v.page.close();

  console.log("\n== D11 link mismatch");
  v = await visit(at("link-trick"));
  check("login page + mismatched link is strong", () => assert.ok(v.kinds.includes("link-mismatch-login")));
  await v.page.close();
  v = await visit(at("honest-shop"));
  check("normal links left alone", () => assert.ok(!v.kinds.some((k) => k.startsWith("link-mismatch"))));
  await v.page.close();

  console.log("\n== D5 click-jacking and fake window");
  v = await visit(at("clickjack"));
  check("invisible frame caught", () => assert.ok(v.kinds.includes("clickjack")));
  await v.page.close();
  v = await visit(at("fake-window"));
  check("browser-in-the-browser caught", () => assert.ok(v.kinds.includes("bitb")));
  await v.page.close();
  v = await visit(at("honest-shop"));
  check("normal page: neither", () => assert.ok(!v.kinds.includes("clickjack") && !v.kinds.includes("bitb")));
  await v.page.close();

  console.log("\n== D7 / D8 payment page scripts");
  v = await visit(at("checkout-skim"), { wait: 800, routes: [["https://cdn-evil.workers.dev/**", "setInterval(()=>{const e=document.querySelector('[name=cardnumber]');if(e)void e.value;},100);"]] });
  await v.page.fill("[name=cardnumber]", "4242424242424242"); await v.page.waitForTimeout(600);
  const k7 = await guards(v.tab);
  check("script from a data-dump host listed", () => assert.ok(k7.includes("skim-host")));
  check("that script reading the card box is strong", () => assert.ok(k7.includes("skim-read")));
  await v.page.close();
  v = await visit(at("checkout-legit"), { routes: [["https://static.hotjar.com/**", "/* replay */"]] });
  await v.page.fill("[name=cardnumber]", "4242424242424242"); await v.page.waitForTimeout(400);
  const k8 = await guards(v.tab);
  check("replay vendor noted as info", () => assert.ok(k8.includes("replay")));
  check("...but nothing scary", () => assert.ok(!k8.includes("skim-read") && !k8.includes("skim-host")));
  await v.page.close();

  console.log("\n== D10 OAuth consent");
  {
    const page = await ctx.newPage();
    await page.route("https://accounts.google.com/**", (r) => r.fulfill({ status: 200, contentType: "text/html", body: "<title>Sign in</title><p>Google hasn't verified this app</p>" }));
    await page.goto("https://accounts.google.com/o/oauth2/v2/auth?client_id=1&scope=https%3A%2F%2Fmail.google.com%2F%20email");
    await page.waitForTimeout(1200);
    const tab = await newestTab(); const k = await guards(tab);
    check("unverified app wanting all your email is strong", () => assert.ok(k.includes("oauth-broad-unverified")));
    await acheck("banner is on screen", async () => assert.equal(await topAt(page, 600, 10), "decoy-protect-host"));
    await page.close();
    const p2 = await ctx.newPage();
    await p2.route("https://accounts.google.com/**", (r) => r.fulfill({ status: 200, contentType: "text/html", body: "<title>Sign in</title>" }));
    await p2.goto("https://accounts.google.com/o/oauth2/v2/auth?client_id=1&scope=openid%20email%20profile"); await p2.waitForTimeout(1000);
    await acheck("basic sign-in scopes: no warning", async () => assert.deepEqual(await guards(await newestTab()), []));
    await p2.close();
  }

  console.log("\n== D4 download guard");
  {
    const page = await ctx.newPage(); page.on("download", () => {});
    await page.goto(at("auto-download")); await page.waitForTimeout(2500);
    const items = await popup.evaluate(() => chrome.downloads.search({}));
    const it = items.find((i) => /setup\.exe/.test(i.url));
    check("download was started", () => assert.ok(it));
    check("...and held (paused) for you to decide", () => assert.ok(it && (it.paused || it.state === "interrupted")));
    await acheck("notice offered Cancel / Keep", async () => assert.equal(await topAt(page, -40, 30), "decoy-protect-host"));
    await acheck("recorded as strong", async () => assert.ok((await guards(await newestTab())).includes("download-exec")));
    await popup.evaluate((id) => chrome.runtime.sendMessage({ type: "dl:cancel", id }), it.id);
    await page.waitForTimeout(500);
    const after = (await popup.evaluate(() => chrome.downloads.search({}))).find((i) => i.id === it.id);
    check("Cancel really cancels", () => assert.ok(!after || after.state === "interrupted" || after.exists === false));
    await page.close();
  }

  console.log("\n== D16 tracker blocking (off by default)");
  {
    const run = async () => {
      const page = await ctx.newPage(); let blocked = false;
      page.on("requestfailed", (r) => { if (/hotjar/.test(r.url()) && /BLOCKED_BY_CLIENT/.test(r.failure()?.errorText || "")) blocked = true; });
      await page.goto(at("pixel-shop")); await page.waitForTimeout(1500); await page.close(); return blocked;
    };
    await acheck("off by default: not blocked by Decoy", async () => assert.equal(await run(), false));
    await popup.evaluate(() => chrome.runtime.sendMessage({ type: "trackers:set", on: true }));
    await acheck("on: replay script blocked by Decoy", async () => assert.equal(await run(), true));
    await popup.evaluate(() => chrome.runtime.sendMessage({ type: "trackers:set", on: false }));
  }

  console.log("\n== D14 / D15 / D12 background logic");
  const pc = await popup.evaluate(() => chrome.runtime.sendMessage({ type: "precheck", text: "Your Canada Post parcel is on hold. Pay the fee within 24 hours: http://canadapost-redeliver-fee.xyz/pay or you will be charged" }));
  check("scam text + look-alike link scores high", () => assert.ok(pc.score >= 45, `score=${pc.score}`));
  const pc2 = await popup.evaluate(() => chrome.runtime.sendMessage({ type: "precheck", text: "See https://github.com/anthropics for the code" }));
  check("plain link to a well-known site is fine", () => assert.ok(pc2.score < 20, `score=${pc2.score}`));
  const pc3 = await popup.evaluate(() => chrome.runtime.sendMessage({ type: "precheck", text: "https://paypal.com@evil-login.xyz/verify" }));
  check("name@ trick caught", () => assert.ok(pc3.reasons.some((r) => /name@/.test(r))));

  console.log(failed ? `\n${failed} FAILED` : "\nALL PROTECT CHECKS PASSED");
  await ctx.close(); server.kill(); process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
