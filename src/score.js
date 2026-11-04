// Turns flags [{id,label,weight,tier}] into a 0-100 risk score.
// Biggest flag counts fully, each extra one 10% less. Then evidence caps:
//   no strong flag          -> at most 35  ("A bit off")
//   one strong flag         -> at most 69  ("Sketchy")
//   "Likely scam" needs 2 strong flags, or a hit on a known-bad list ("feed") or the shared list ("crowd").
const WEAK_ONLY_CAP = 35;
const ONE_STRONG_CAP = 69;

export function computeScore(flags, { trustKind = null, trusted = false } = {}) {
  const kind = trustKind || (trusted ? "popular" : null);
  const sorted = [...flags].sort((a, b) => b.weight - a.weight);
  let total = 0;
  sorted.forEach((f, i) => { total += f.weight * Math.pow(0.9, i); });
  let score = Math.min(100, Math.round(total));

  const strong = flags.filter((f) => f.tier === "strong").length;
  const feed = flags.some((f) => f.id === "feed" || f.id === "crowd");
  let capped = null;
  if (strong === 0 && score > WEAK_ONLY_CAP) { score = WEAK_ONLY_CAP; capped = "weak-only"; }
  else if (!feed && strong < 2 && score > ONE_STRONG_CAP) { score = ONE_STRONG_CAP; capped = "one-strong"; }

  return { score, capped, strong, ...level(score, kind), flags: sorted };
}

const TRUST_LABELS = {
  popular: ["Well-known site", "One of the most visited sites on the web."],
  institution: ["Government / education site", "Official institution. Page checks skipped."],
  you: ["Trusted by you", "You marked this site as trusted."],
};

export function level(score, kind = null) {
  if (score < 20) {
    const [lv, sub] = TRUST_LABELS[kind] || ["Looks fine", "No major red flags found. That isn't a guarantee: brand-new scams can look clean."];
    return { level: lv, color: "#7ee2a0", sub };
  }
  if (score < 45) return { level: "A bit off", color: "#ffd166", sub: "Some warning signs. Be careful with personal details." };
  if (score < 70) return { level: "Sketchy", color: "#ff9f43", sub: "Multiple red flags. Don't enter real info." };
  return { level: "Likely scam", color: "#ff5d5d", sub: "Strong scam signals. Leave this page." };
}
