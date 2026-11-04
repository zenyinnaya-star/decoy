// Bundled into a page by scripts/crawl.mjs: runs the same scoring the extension uses, outside the extension.
import { scan, domainFlags } from "./scanner.js";
import { assess } from "./assess.js";
import { computeScore } from "./score.js";
import ALLOW from "./allowlist.json";
import WORDS from "./common-words.json";

const allow = new Set(ALLOW), common = new Set(WORDS);
window.__decoyJudge = () => {
  const s = scan(document, location);
  const flags = [...domainFlags(s.host, common).flags, ...s.flags];
  const a = assess({ ...s, flags }, { isTrusted: (d) => allow.has(d) });
  const r = computeScore(a.flags, { trustKind: a.trustKind });
  return { host: s.host, score: r.score, level: r.level, sensitive: s.sensitive, trust: a.trustKind, flags: r.flags.map((f) => `${f.id}${f.tier === "strong" ? "!" : ""}`) };
};
