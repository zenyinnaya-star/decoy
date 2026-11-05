// Site security check end to end: popup button -> page scan + the site's own headers -> readable result.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const DIST = require("node:path").resolve(__dirname, "../../dist");
(async () => {
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = sw.url().split("/")[2];
  const seen = []; // proof of "one request, to the site itself"
  await ctx.route(/\.test/, (r) => {
    const rq = r.request(); seen.push(rq.method() + " " + rq.url());
    if (rq.url().includes("old-shop")) return r.fulfill({ contentType: "text/html", headers: { server: "Apache/2.2.15 (CentOS)" }, body: `<title>Shop</title><script src="/jquery-1.12.4.min.js"></script><form method="get"><input type="password"></form><script src="http://cdn.other.test/a.js"></script>` });
    return r.fulfill({ contentType: "text/html", headers: { "strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff" }, body: "<title>Good</title><p>hi</p>" });
  });
  async function run(url) {
    const page = await ctx.newPage(); await page.goto(url); await page.waitForTimeout(800);
    const tab = await sw.evaluate(async () => (await chrome.tabs.query({ active: true })).pop().id);
    const pop = await ctx.newPage(); await pop.goto(`chrome-extension://${id}/popup.html?tab=${tab}`);
    await pop.waitForTimeout(600); await pop.click("#secbtn"); await pop.waitForSelector("#secbox:not([hidden])");
    if (process.env.SHOT && url.includes("old-shop")) { await pop.setViewportSize({ width: 380, height: 900 }); await pop.screenshot({ path: process.env.SHOT, scale: "device" }); }
    return { pop, text: await pop.textContent("#secbox"), grade: await pop.textContent("#secbox .grade") };
  }
  seen.length = 0;
  let r = await run("https://good-site.test/");
  assert.equal(r.grade, "A"); assert.match(r.text, /Nothing found/);
  assert.deepEqual(seen.filter((s) => /^HEAD/.test(s)), ["HEAD https://good-site.test/"], "one HEAD request, to the same site: " + seen);
  console.log("   ok   well-built site: grade A, nothing found, one request to the site itself");
  r = await run("https://old-shop.test/");
  assert.match(r.text, /jQuery 1\.12\.4/); assert.match(r.text, /password in the web address/i); assert.match(r.text, /over http/i); assert.match(r.text, /very old/i);
  assert.ok(["D", "F"].includes(r.grade), "grade " + r.grade);
  console.log("   ok   weak site: grade", r.grade, "with jQuery, GET password form, http script, old server");
  await ctx.close(); console.log("\nSITESEC OK");
})().catch((e) => { console.error(e); process.exit(1); });
