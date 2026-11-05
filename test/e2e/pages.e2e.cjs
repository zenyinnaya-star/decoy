// Popup on pages Chrome won't let extensions touch: must explain why, not say "reload".
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");
(async () => {
  const ctx = await chromium.launchPersistentContext("", { headless: false, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`, "--headless=new"] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker");
  const id = new URL(sw.url()).host;
  for (const [url, expect] of [["chrome://version", /Chrome's own page/], ["chrome://settings", /Chrome's own page/]]) {
    const pg = await ctx.newPage(); await pg.goto(url).catch(() => {});
    const tabId = await sw.evaluate(async () => (await chrome.tabs.query({ active: true })).map((t) => t.id).pop());
    const pop = await ctx.newPage(); await pop.goto(`chrome-extension://${id}/popup.html?tab=${tabId}`);
    await pop.waitForFunction(() => document.querySelector("#level").textContent !== "Scanning…");
    const lv = await pop.textContent("#level");
    assert.match(lv, expect, `${url}: got ${lv}`);
    console.log("   ok  ", url, "→", lv, "|", (await pop.textContent("#sub")).slice(0, 60));
  }
  await ctx.close(); console.log("\nPAGES OK");
})().catch((e) => { console.error(e); process.exit(1); });
