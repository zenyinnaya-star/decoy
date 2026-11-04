// Builds data/allowlist.json (top 50k CrUX sites, by registrable domain)
// and test/fixtures/legit-domains.json (ranks 50k-500k, used to measure false positives).
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { gunzipSync } from "zlib";
import { getDomain } from "tldts";

const rows = gunzipSync(readFileSync("data/crux.csv.gz")).toString().split("\n").slice(1);
const top = new Set(), mid = new Set();
for (const r of rows) {
  const [origin, rank] = r.split(",");
  if (!origin) continue;
  let host; try { host = new URL(origin).hostname; } catch { continue; }
  const d = getDomain(host, { allowPrivateDomains: true });
  if (!d) continue;
  (+rank <= 50000 ? top : mid).add(d);
}
for (const d of top) mid.delete(d);
writeFileSync("src/allowlist.json", JSON.stringify([...top].sort()));
mkdirSync("test/fixtures", { recursive: true });
writeFileSync("test/fixtures/legit-domains.json", JSON.stringify([...mid].sort()));
console.log("allowlist", top.size, "legit test set", mid.size);
