// A5: check Decoy's PAGE scoring against real sites. Run this on your own machine (needs internet):
//   npm run crawl -- --n 500                    random sites from data/crux.csv.gz (beyond the top-40k safe list)
//   npm run crawl -- --urls my-sites.txt        your own list, one URL per line
// Prints how many real sites got flagged and why. Goal: under 1% with any flag, ~0 above "A bit off".
import { build } from "esbuild";
import { createRequire } from "module";
import { readFileSync, writeFileSync } from "fs";
import { gunzipSync } from "zlib";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const N = +arg("n", 300), CONC = +arg("conc", 4), OUT = arg("out", "crawl-report.md"), FILE = arg("urls", null), TO = +arg("timeout", 15000);

const bundle = (await build({ entryPoints: ["src/crawl-entry.js"], bundle: true, write: false, format: "iife", target: "chrome111", minify: true })).outputFiles[0].text;

let urls;
if (FILE) urls = readFileSync(FILE, "utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
else {
  const allow = new Set(JSON.parse(readFileSync("src/allowlist.json", "utf8")));
  const rows = gunzipSync(readFileSync("data/crux.csv.gz")).toString().split("\n").slice(1).map((l) => l.split(",")[0]).filter(Boolean);
  const pool = rows.map((o) => o.replace(/^https?:\/\//, "")).filter((h) => !allow.has(h.replace(/^www\./, "")));
  for (let i = pool.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [pool[i], pool[j]] = [pool[j], pool[i]]; }
  urls = pool.slice(0, N).map((h) => `https://${h}/`);
}

const browser = await chromium.launch({ channel: "chromium", headless: true });
const results = []; let next = 0;
async function worker() {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  while (next < urls.length) {
    const url = urls[next++];
    const page = await ctx.newPage();
    try {
      await page.goto(url, { timeout: TO, waitUntil: "domcontentloaded" });
      await page.waitForTimeout(800);
      await page.addScriptTag({ content: bundle });
      results.push({ url, ...(await page.evaluate(() => window.__decoyJudge())) });
    } catch (e) { results.push({ url, error: String(e.message).split("\n")[0].slice(0, 80) }); }
    await page.close().catch(() => {});
    if (results.length % 25 === 0) console.log(`  ${results.length}/${urls.length}`);
  }
  await ctx.close();
}
await Promise.all(Array.from({ length: CONC }, worker));
await browser.close();

const ok = results.filter((r) => !r.error);
const flagged = ok.filter((r) => r.flags.length), noticed = ok.filter((r) => r.score >= 20), sketchy = ok.filter((r) => r.score >= 45);
const pct = (n) => (ok.length ? ((100 * n) / ok.length).toFixed(1) : "0") + "%";
const md = [
  `# Decoy crawl report`, ``, `Scanned ${ok.length} sites (${results.length - ok.length} failed to load).`, ``,
  `| | count | share |`, `|---|---|---|`,
  `| any flag | ${flagged.length} | ${pct(flagged.length)} |`, `| "A bit off" or worse | ${noticed.length} | ${pct(noticed.length)} |`, `| "Sketchy" or worse | ${sketchy.length} | ${pct(sketchy.length)} |`, ``,
  `## Flagged sites`, ``, `| site | score | level | flags |`, `|---|---|---|---|`,
  ...flagged.sort((a, b) => b.score - a.score).map((r) => `| ${r.host} | ${r.score} | ${r.level} | ${r.flags.join(", ")} |`),
].join("\n");
writeFileSync(OUT, md);
console.log(md.split("\n").slice(0, 12).join("\n"), `\n\nFull report: ${OUT}`);
