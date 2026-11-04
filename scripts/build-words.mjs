// Common tokens in real domain names (trained on even-indexed legit domains + allowlist).
// A token that is common on real sites is not a typo of a brand ("finance" vs "binance").
import { readFileSync, writeFileSync } from "fs";
import { parse } from "tldts";
import { BRANDS } from "../src/brands.js";
const legit = JSON.parse(readFileSync("test/fixtures/legit-domains.json"));
const allow = JSON.parse(readFileSync("src/allowlist.json"));
const train = [...allow, ...legit.filter((_, i) => i % 2 === 0)];
const freq = new Map();
for (const d of train) {
  const lab = parse(d, { allowPrivateDomains: true }).domainWithoutSuffix || "";
  for (const t of new Set(lab.split(/[^a-z0-9]+/))) if (t.length >= 4 && /^[a-z]+$/.test(t)) freq.set(t, (freq.get(t) || 0) + 1);
}
const brands = new Set(BRANDS);
const words = [...freq].filter(([t, n]) => n >= 8 && !brands.has(t)).map(([t]) => t).sort();
writeFileSync("src/common-words.json", JSON.stringify(words));
console.log("common words:", words.length, "bytes:", JSON.stringify(words).length);
