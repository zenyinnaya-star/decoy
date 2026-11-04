import { classify } from "./destinations.js";
import { parseHost } from "./scanner.js";
import { BRANDS } from "./brands.js";

const BRAND_SET = new Set(BRANDS);
const NICE = { email: "email", password: "password", phone: "phone number", card: "card number" };
const HASHES = new Set(["sha256", "sha1", "md5"]);
export const LIMIT = "Decoy only sees what your browser sends. A site can still pass your data on from its own servers.";

const listify = (a) => (a.length <= 1 ? a[0] : `${a.slice(0, -1).join(", ")} and ${a[a.length - 1]}`);
const cap = (s) => s[0].toUpperCase() + s.slice(1);

// One request that carried a dummy value -> one human-readable finding.
// raw = { url, via, hits: [{kind, enc}], beforeSubmit }
export function judgeFinding(raw, pageHost) {
  const c = classify(raw.url, pageHost);
  const kinds = [...new Set(raw.hits.map((h) => h.kind))];
  const hashed = raw.hits.every((h) => HASHES.has(h.enc));
  const secret = kinds.includes("password") || kinds.includes("card");
  const what = listify(kinds.map((k) => NICE[k] || k)) + (hashed ? " (scrambled with a hash)" : "");
  const early = raw.beforeSubmit && c.kind !== "first" && c.kind !== "provider";
  const when = early ? ", before you pressed submit" : "";
  const where = {
    first: "this site", provider: `${c.host} (a payment/sign-in provider)`,
    analytics: `${c.host} (an ad/analytics service, common on real sites)`,
    formsvc: `${c.host} (a form/email service)`,
    grabber: `${c.host} (${c.note || "a place attackers dump stolen data"})`,
    suspicious: `${c.host} (a free host that scam kits often use)`,
    unknown: `${c.host} (a different site than the one you're on)`,
  }[c.kind];

  let severity;
  if (c.insecure) severity = "strong"; // anything sent over plain http
  else {
    severity = {
      first: "ok", provider: "ok",
      analytics: secret ? "strong" : "info",
      formsvc: secret ? "strong" : early ? "warn" : "info",
      grabber: "strong",
      suspicious: secret || early ? "strong" : "warn",
      unknown: secret || early ? "strong" : "warn",
    }[c.kind];
  }
  const showWhen = early && (severity === "warn" || severity === "strong"); // not worth mentioning for harmless pixels
  const text = `${cap(what)} sent to ${where}${showWhen ? when : ""}${c.insecure ? ", without encryption" : ""}.`;
  return { severity, text, host: c.host, kind: c.kind, kinds, beforeSubmit: !!raw.beforeSubmit, via: raw.via };
}

const ORDER = { strong: 0, warn: 1, info: 2, ok: 3 };

// state = { host, submitted, hadPassword, findings: [raw], pages: [{host, domain, afterSubmit, extraAsk}] }
export function buildVerdict(state, { pageScore = 0 } = {}) {
  const items = [];
  const seen = new Set();
  const okHosts = new Set();

  // One line per destination: merge everything that went to the same place at the same stage.
  const groups = new Map();
  for (const raw of state.findings || []) {
    let host = raw.url;
    try { host = new URL(raw.url).host; } catch {}
    const key = `${host}|${raw.beforeSubmit ? 1 : 0}`;
    const g = groups.get(key);
    if (g) g.hits = [...g.hits, ...raw.hits]; else groups.set(key, { ...raw, hits: [...raw.hits] });
  }

  for (const raw of groups.values()) {
    const f = judgeFinding(raw, state.host);
    if (f.severity === "ok") { okHosts.add(f.kind === "first" ? "this site" : f.host); continue; }
    const key = `${f.host}|${f.kinds.join()}|${f.beforeSubmit}|${f.severity}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push(f);
  }

  const myDomain = parseHost(state.host).domain || state.host;
  for (const p of state.pages || []) {
    if (!p.afterSubmit) continue;
    const d = parseHost(p.host).domain || p.host;
    const label = parseHost(p.host).label || "";
    if (d !== myDomain && BRAND_SET.has(label) && !seen.has(`redirect|${label}`)) {
      seen.add(`redirect|${label}`);
      items.push({ severity: "strong", kind: "redirect", host: p.host,
        text: `After you submitted, the site sent you to the real ${label} site. Phishing pages do this so you don't notice.` });
    }
    if (state.hadPassword && p.extraAsk?.length && !seen.has("extraask")) {
      seen.add("extraask");
      items.push({ severity: "warn", kind: "extraask", host: p.host,
        text: `After you "logged in", the next page asked for ${listify(p.extraAsk)}.` });
    }
  }

  items.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const count = (s) => items.filter((i) => i.severity === s).length;
  const strong = count("strong"), warn = count("warn");

  let status, title, sub;
  if (!state.submitted && !items.length) {
    status = "waiting"; title = "Watching…";
    sub = "Submit the form yourself. Decoy will show where the dummy details go.";
  } else if (strong || (pageScore >= 70 && warn)) {
    status = "grabber"; title = "Looks like a data grabber";
    sub = "The dummy details went somewhere they shouldn't, or the site behaves like a phishing kit. Don't use real info here.";
  } else if (warn) {
    status = "careful"; title = "Be careful";
    sub = "Some of the dummy data went to other sites.";
  } else {
    status = "clean"; title = "No leak seen";
    sub = okHosts.size
      ? `The dummy details only went to ${listify([...okHosts])}${items.some((i) => i.severity === "info") ? " and ad/analytics services" : ""}.`
      : "No request carrying the dummy details was seen.";
  }
  return { status, title, sub, items, submitted: !!state.submitted, limit: LIMIT };
}
