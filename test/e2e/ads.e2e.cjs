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


  // ---- redirects, ad links and hijack layers ----
  await popup.evaluate(() => chrome.runtime.sendMessage({ type: "ads:set", on: true }));
  const HJ = `<title>Hijack</title><a id="good" href="https://other-site.test/page">Real link</a> <a id="adlink" href="https://ads.doubleclick.net/c?x=1">Download now</a>
    <button id="btn">Sign in</button><div id="layer" style="position:fixed;inset:0;opacity:0;z-index:99999"></div><p id="t">text</p>`;
  await ctx.route(/hijack\.test|other-site\.test/, (r) => r.fulfill({ contentType: "text/html", body: r.request().url().includes("other-site") ? "<title>OTHER</title>" : HJ }));
  const hj = async () => { const p = await ctx.newPage(); await p.goto("https://hijack.test/"); await p.waitForTimeout(800); return p; };

  p = await hj(); // 1: timer redirect to another site, no click
  await p.evaluate(() => { document.getElementById("layer").remove(); setTimeout(() => (location.href = "https://other-site.test/ad"), 6000); });
  await p.waitForTimeout(7000);
  assert.equal(new URL(p.url()).hostname, "hijack.test", "forced redirect stopped: " + p.url());
  console.log("   ok   forced redirect to another site stopped");
  await p.click("#good"); await p.waitForTimeout(800);
  assert.equal(new URL(p.url()).hostname, "other-site.test", "real link click still works");
  console.log("   ok   real link click still works"); await p.close();

  p = await hj(); // 2: link to an ad network
  await p.evaluate(() => document.getElementById("layer").remove());
  await p.click("#adlink"); await p.waitForTimeout(500);
  assert.equal(new URL(p.url()).hostname, "hijack.test", "ad link not followed: " + p.url());
  console.log("   ok   link to an ad network stopped"); await p.close();

  p = await hj(); // 3: invisible layer
  await p.mouse.click(200, 200); await p.waitForTimeout(300);
  assert.equal(await p.evaluate(() => getComputedStyle(document.getElementById("layer")).display), "none", "invisible layer removed");
  console.log("   ok   invisible click-hijack layer removed"); await p.close();

  p = await hj(); // 4: script redirect right after a real click (sign-in style) is left alone
  await p.evaluate(() => { document.getElementById("layer").remove(); document.getElementById("btn").addEventListener("click", () => (location.href = "https://other-site.test/signed-in")); });
  await p.click("#btn"); await p.waitForTimeout(800);
  assert.equal(new URL(p.url()).hostname, "other-site.test", "redirect after a click allowed");
  console.log("   ok   redirect right after your own click (sign-in style) allowed"); await p.close();

  await popup.evaluate(() => chrome.runtime.sendMessage({ type: "ads:set", on: false }));
  p = await load(); s = await state(p); assert.ok(s.ran.includes("ad.js") && s.slot === "block"); await p.close();
  console.log("   ok   off again: back to normal");
  await ctx.close(); console.log("\nADS OK");
})().catch((e) => { console.error(e); process.exit(1); });
