import { readFileSync } from "fs";
import { JSDOM } from "jsdom";
import { scan, domainFlags } from "../src/scanner.js";
import { assess } from "../src/assess.js";
import { computeScore } from "../src/score.js";

export const common = new Set(JSON.parse(readFileSync("src/common-words.json")));
const allow = new Set(JSON.parse(readFileSync("src/allowlist.json")));
export const isTrusted = (d) => allow.has(d);

export const domainIds = (host) => domainFlags(host, common).flags.map((f) => f.id);

// Same pipeline as the extension: page scan -> + domain flags -> assess -> score.
export function evaluate(url, html, { ageDays = 4000 } = {}) {
  const dom = new JSDOM(html, { url });
  const loc = new URL(url);
  const s = scan(dom.window.document, loc);
  s.flags = [...domainFlags(loc.hostname, common).flags, ...s.flags];
  const a = assess(s, { isTrusted, ageDays });
  return { ...computeScore(a.flags, { trustKind: a.trustKind }), trusted: a.trusted, trustKind: a.trustKind };
}
