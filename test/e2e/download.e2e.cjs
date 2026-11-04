// Download check in real Chromium: finished downloads get a verdict toast; the popup can check a file locally.
const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const DIST = path.resolve(__dirname, "../../dist");
const PORT = 18085;
const at = (n, p = "/") => `http://${n}.localhost:${PORT}${p}`;
let failed = 0;
const acheck = async (name, fn) => { try { await fn(); console.log(`   ok   ${name}`); } catch (e) { failed++; console.log(`   FAIL ${name}: ${e.message.split("\n")[0]}`); } };

(async () => {
  const server = spawn("node", ["testbed/server.mjs"], { env: { ...process.env, PORT: String(PORT) }, stdio: ["ignore", "inherit", "inherit"], cwd: path.resolve(__dirname, "../..") });
  await new Promise((r) => setTimeout(r, 700));
  const ctx = await chromium.launchPersistentContext("", { channel: "chromium", headless: true, acceptDownloads: true, args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`] });
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const id = sw.url().split("/")[2];
  const popup = await ctx.newPage(); await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.evaluate((b) => chrome.storage.local.set({ mode: "off", testReadBase: b }), at("download-lab", "/files/"));
  const results = () => popup.evaluate(() => chrome.runtime.sendMessage({ type: "dl:last" }));
  const topAt = (page) => page.evaluate(() => document.elementFromPoint(innerWidth - 40, 30)?.id || "");

  console.log("\n== DOWNLOAD CHECK: real downloads");
  const page = await ctx.newPage(); await page.goto(at("download-lab", "/"));
  for (const sel of ["#d1", "#d2", "#d3", "#d4", "#d5"]) {
    const dl = page.waitForEvent("download"); await page.click(sel); await (await dl).path(); await page.waitForTimeout(900);
  }
  const r = Object.fromEntries((await results()).map((x) => [x.name, x.verdict]));
  await acheck("program wearing a .pdf name: problem", async () => assert.equal(r["invoice.pdf"], "problem"));
  await acheck("zip with invoice.pdf.exe inside: problem", async () => assert.equal(r["photos.zip"], "problem"));
  await acheck("zip with setup.exe inside: be careful", async () => assert.equal(r["bundle.zip"], "careful"));
  await acheck("plain PDF: nothing suspicious", async () => assert.equal(r["guide.pdf"], "nothing"));
  await acheck("plain text: nothing suspicious", async () => assert.equal(r["notes.txt"], "nothing"));
  await acheck("no file contents or paths stored", async () => assert.ok(!JSON.stringify(await results()).includes("MZ")));

  console.log("\n== DOWNLOAD CHECK: pop-up on the page");
  const p2 = await ctx.newPage(); await p2.goto(at("download-lab", "/"));
  await p2.bringToFront();
  const dl = p2.waitForEvent("download"); await p2.click("#d1"); await (await dl).path(); await p2.waitForTimeout(1500);
  await acheck("problem toast appears on the page", async () => assert.equal(await topAt(p2), "decoy-protect-host"));
  const p3 = await ctx.newPage(); await p3.goto(at("download-lab", "/")); await p3.bringToFront();
  const dl3 = p3.waitForEvent("download"); await p3.click("#d5"); await (await dl3).path(); await p3.waitForTimeout(1500);
  await acheck("harmless text file: no pop-up", async () => assert.notEqual(await topAt(p3), "decoy-protect-host"));

  console.log("\n== DOWNLOAD CHECK: off switch");
  await popup.evaluate(() => chrome.storage.local.set({ off: { dlscan: true } }));
  const before = (await results()).length;
  const dl4 = p3.waitForEvent("download"); await p3.click("#d2"); await (await dl4).path(); await p3.waitForTimeout(1000);
  await acheck("switch off: nothing checked", async () => assert.equal((await results()).length, before));
  await popup.evaluate(() => chrome.storage.local.set({ off: {} }));

  console.log("\n== POPUP: check a file");
  const exe = Buffer.alloc(1024); exe[0] = 0x4d; exe[1] = 0x5a;
  const f = path.join(require("node:os").tmpdir(), "invoice.pdf"); fs.writeFileSync(f, exe);
  await popup.reload();
  await popup.locator("summary, #more-toggle").first().click().catch(() => {});
  await popup.setInputFiles("#filepick", f);
  await popup.waitForTimeout(800);
  await acheck("popup flags a disguised program", async () => assert.match(await popup.textContent("#fileout"), /Problem found/));
  await acheck("popup shows a SHA-256", async () => assert.match(await popup.textContent("#fileout"), /SHA-256: [0-9a-f]{64}/));
  const f2 = path.join(require("node:os").tmpdir(), "notes.txt"); fs.writeFileSync(f2, "buy milk"); await popup.setInputFiles("#filepick", f2); await popup.waitForTimeout(500);
  await acheck("popup: plain text says not a guarantee", async () => assert.match(await popup.textContent("#fileout"), /not a guarantee/));

  await ctx.close(); server.kill();
  console.log(failed ? `\n${failed} FAILED` : "\nALL PASSED"); process.exit(failed ? 1 : 0);
})();
