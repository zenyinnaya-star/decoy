// False-positive sweep: domain checks over the HELD-OUT half of real sites (odd indices;
// the common-word list was built from the even half, so this isn't graded on its own homework).
import { readFileSync } from "fs";
import { domainFlags } from "../src/scanner.js";
const common = new Set(JSON.parse(readFileSync("src/common-words.json")));
const doms = JSON.parse(readFileSync("test/fixtures/legit-domains.json")).filter((_, i) => i % 2 === 1);
const STRONG = new Set(["brandlure", "lookalike", "subbrand", "punycode"]);
const hits = {}, samples = {};
let strong = 0;
for (const d of doms) {
  const { flags } = domainFlags(d, common);
  if (flags.some((f) => STRONG.has(f.id))) strong++;
  for (const f of flags) {
    hits[f.id] = (hits[f.id] || 0) + 1;
    (samples[f.id] ||= []).length < +(process.argv[2] || 15) && samples[f.id].push(`${d}  →  ${f.label}`);
  }
}
console.log(`held-out legit domains: ${doms.length}  brand/lookalike-flagged: ${strong} (${(strong / doms.length * 100).toFixed(3)}%)`);
console.log(hits);
for (const id of STRONG) console.log(`\n--- ${id}\n` + (samples[id] || []).join("\n"));
