// How much does Decoy slow pages down? Same heavy page with and without the extension.
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const path = require("node:path");
const DIST = path.resolve(__dirname, "../../dist");
const PORT = 18085;
const url = `http://heavy.localhost:${PORT}/`;
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];

(async () => {
  const server = spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(PORT) }, stdio: "ignore", cwd: path.resolve(__dirname, "../..") });
  await new Promise((r) => setTimeout(r, 700));
  const measure = async (withExt) => {
    const quiet = ["--disable-background-networking", "--disable-component-update", "--no-first-run", "--disable-sync"];
    const args = withExt ? [...quiet, `--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] : quiet;
    const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, args });
    if (withExt) { let [sw] = ctx.serviceWorkers(); if (!sw) await ctx.waitForEvent("serviceworker", { timeout: 15000 }); }
    const loads = [];
    for (let i = 0; i < 5; i++) {
      const page = await ctx.newPage();
      const t0 = Date.now(); await page.goto(url, { waitUntil: "load" }); loads.push(Date.now() - t0);
      if (i === 4) {
        await page.waitForTimeout(1500);
        var micro = await page.evaluate(() => {
          const inp = document.querySelector("input"); let n = 0; const t = performance.now();
          for (let i = 0; i < 200000; i++) n += inp.value.length;
          const readNs = ((performance.now() - t) * 1e6) / 200000;
          return { readNs: Math.round(readNs), fetchNative: /\[native code\]/.test(String(window.fetch)), clipNative: /\[native code\]/.test(String(Clipboard.prototype.writeText)) };
        });
      }
      await page.close();
    }
    await ctx.close();
    return { load: med(loads), micro };
  };
  const base = await measure(false), ext = await measure(true);
  console.log(`page load (median of 5): without Decoy ${base.load} ms, with Decoy ${ext.load} ms, overhead ${ext.load - base.load} ms`);
  console.log(`reading an input's .value: without ${base.micro.readNs} ns, with ${ext.micro.readNs} ns`);
  console.log(`wrapped fetch looks native to the page: ${ext.micro.fetchNative}; clipboard.writeText looks native: ${ext.micro.clipNative}`);
  const ok = ext.load - base.load < 400 && ext.micro.readNs < 3000 && ext.micro.fetchNative && ext.micro.clipNative;
  console.log(ok ? "PERF OK" : "PERF PROBLEM");
  server.kill(); process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(1); });
