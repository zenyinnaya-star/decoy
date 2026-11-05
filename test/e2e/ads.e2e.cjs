// Ad blocker: network rules, hidden ad slots, pop-up blocking. Off by default, on after the switch.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const DIST = require("node:path").resolve(__dirname, "../../dist");
const PAGE = `<title>News</title><p id="story">Real article text</p><ins class="adsbygoogle" id="slot" style="display:block;height:90px">AD</ins>
<script src="https://ads.doubleclick.net/ad.js"></script><script src="https://cdn.example-news.test/app.js"></script><script src="/own.js"></script>`;
(async () => {
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  await ctx.route(/\.test\/|doubleclick\.net/, (r) => {
    const u = r.request().url();
    if (u.endsWith("/")) return r.fulfill({ contentType: "text/html", body: PAGE });
    return r.fulfill({ contentType: "application/javascript", body: `window.__ran=(window.__ran||[]);window.__ran.push(${JSON.stringify(u.split("/").pop())});` });
  });
  const load = async () => { const p = await ctx.newPage(); await p.goto("https://news-site.test/"); await p.waitForTimeout(800); return p; };
  const state = (p) => p.evaluate(() => ({ ran: window.__ran || [], slot: getComputedStyle(document.getElementById("slot")).display, story: getComputedStyle(document.getElementById("story")).display }));

  let p = await load(); let s = await state(p);
  assert.ok(s.ran.includes("ad.js"), "ad script loads while blocker is off"); assert.equal(s.slot, "block"); await p.close();
  console.log("   ok   off by default: ads load");

  assert.equal((await popup.evaluate(() => chrome.runtime.sendMessage({ type: "ads:set", on: true }))).on, true);
  p = await load(); s = await state(p);
  assert.ok(!s.ran.includes("ad.js"), "ad script blocked: " + s.ran);
  assert.ok(s.ran.includes("app.js") && s.ran.includes("own.js"), "site's own and other third-party scripts untouched: " + s.ran);
  assert.equal(s.slot, "none", "empty ad slot hidden"); assert.equal(s.story, "block", "real content untouched");
  console.log("   ok   on: ad script blocked, own/other scripts load, ad slot hidden, article untouched");

  // Playwright's evaluate counts as a user gesture for 5s, so wait it out: a timer-opened window has no real click behind it.
  const noClick = await p.evaluate(() => new Promise((r) => setTimeout(() => r(window.open("https://ads.example.test/popup") === null), 6000)));
  assert.ok(noClick, "window.open with no click is blocked");
  console.log("   ok   pop-up opened by a timer (no click) is blocked");
  await p.evaluate(() => { document.getElementById("story").addEventListener("click", () => { window.__opened = window.open("about:blank") !== null; }); });
  await p.click("#story");
  assert.equal(await p.evaluate(() => window.__opened), true, "window opened by a real click still works");
  console.log("   ok   window opened by a real click still works");
  await p.close();

  await popup.evaluate(() => chrome.runtime.sendMessage({ type: "ads:set", on: false }));
  p = await load(); s = await state(p); assert.ok(s.ran.includes("ad.js") && s.slot === "block"); await p.close();
  console.log("   ok   off again: back to normal");
  await ctx.close(); console.log("\nADS OK");
})().catch((e) => { console.error(e); process.exit(1); });
