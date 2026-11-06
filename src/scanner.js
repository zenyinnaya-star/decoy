import { parse } from "tldts";
import punycode from "punycode/punycode.es6.js";
const { toUnicode } = punycode;
import { BRANDS, LURE_WORDS, GENERIC_BRANDS, NO_TYPO } from "./brands.js";
import { isLoopback } from "./trust.js";

const BRAND_SET = new Set(BRANDS);
const SUS_TLDS = new Set([
  "xyz", "top", "click", "link", "gq", "tk", "ml", "cf", "ga", "work", "support", "icu", "buzz",
  "rest", "fit", "cam", "monster", "sbs", "cyou", "cfd", "bond", "quest", "zip", "mov", "country",
]);

export function parseHost(host) {
  const p = parse(host, { allowPrivateDomains: true });
  return {
    host,
    domain: p.domain, // registrable, e.g. foo.github.io / example.co.uk
    label: p.domainWithoutSuffix, // e.g. "example"
    suffix: p.publicSuffix,
    sub: p.subdomain || "",
    isIp: !!p.isIp,
  };
}

// Visual / leet normalisation: paypa1 -> paypal, rnicrosoft -> microsoft
const normalize = (s) =>
  s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l")
    .replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b");

// Bounded Levenshtein: returns >max early.
export function lev(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

const tokens = (s) => s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

// Which brand (if any) does this token imitate?  Returns { brand, how } or null.
function imitates(tok, common) {
  if (BRAND_SET.has(tok) || common.has(tok) || !/[a-z]/.test(tok)) return null;
  const n = normalize(tok);
  if (n !== tok && n.length >= 5 && BRAND_SET.has(n) && !GENERIC_BRANDS.has(n)) return { brand: n, how: "lookalike characters" };
  // Typos only for longer brands, where a 1-2 edit collision with a real word is rare.
  for (const b of BRANDS) {
    if (b.length < 6 || GENERIC_BRANDS.has(b) || NO_TYPO.has(b)) continue;
    const max = b.length >= 9 ? 2 : 1;
    if (lev(n, b, max) <= max) return { brand: b, how: "misspelling" };
  }
  return null;
}

// "appleidverify" -> apple + id + verify. True if s is made only of lure words.
function allLure(s) {
  if (!s) return true;
  for (let i = 2; i <= s.length; i++) if (LURE_WORDS.has(s.slice(0, i)) && allLure(s.slice(i))) return true;
  return false;
}
function gluedBrand(toks) {
  for (const t of toks)
    for (const b of BRANDS) {
      if (b.length < 5 || GENERIC_BRANDS.has(b) || t === b) continue;
      if (t.startsWith(b) && allLure(t.slice(b.length))) return b;
      if (t.endsWith(b) && allLure(t.slice(0, -b.length))) return b;
    }
  return null;
}

// Letters from other alphabets that look identical to Latin ones.
const CONFUSABLE = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
  "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "ν": "v", "ο": "o", "ρ": "p", "α": "a", "ι": "i",
  "κ": "k", "τ": "t", "υ": "u", "ɡ": "g", "ɑ": "a",
};
const LATIN = /[a-z]/;
const NON_ASCII = /[^\x00-\x7f]/;

// Only risky if the label is built to look like plain English letters.
// Real non-English domains (Russian, Chinese, Arabic...) are left alone.
function idnRisk(label) {
  let u;
  try { u = toUnicode(label); } catch { return null; }
  const chars = [...u].filter((c) => c !== "-" && !/\d/.test(c));
  const foreign = chars.filter((c) => NON_ASCII.test(c));
  if (!foreign.length) return null;
  const skeleton = [...u].map((c) => CONFUSABLE[c] || c).join("");
  if (BRAND_SET.has(skeleton) || BRAND_SET.has(normalize(skeleton)))
    return { label: `Address spells "${skeleton}" with look-alike foreign letters`, weight: 45, brand: skeleton };
  const allConfusable = foreign.every((c) => CONFUSABLE[c]);
  const mixed = chars.some((c) => LATIN.test(c));
  if (allConfusable && mixed) return { label: "Address mixes English letters with look-alike foreign ones", weight: 25 };
  return null;
}

// Domain-only checks (no DOM). Pure, so it can be tested against huge domain lists.
export function domainFlags(host, common = new Set()) {
  const flags = [];
  const add = (id, label, weight, extra) => flags.push({ id, label, weight, tier: "weak", ...extra });
  const h = parseHost(host.toLowerCase());

  if (h.isIp) {
    if (!/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) add("ip", "Site is a raw IP address", 25);
    return { h, flags };
  }
  if (!h.domain) return { h, flags }; // localhost, intranet names: nothing to judge
  if (/(^|\.)translate\.goog$/.test(h.suffix)) return { h, flags }; // Google Translate proxy
  if (BRAND_SET.has(h.suffix)) return { h, flags }; // brand-owned endings: .google, .apple, .amazon

  const idn = [h.label, ...h.sub.split(".")].filter((l) => l.startsWith("xn--")).map(idnRisk).find(Boolean);
  if (idn) add("punycode", idn.label, idn.weight, idn.brand ? { brand: idn.brand, tier: "strong" } : {});
  if (SUS_TLDS.has(h.suffix)) add("tld", `Uses a cheap, often-abused ending (.${h.suffix})`, 8);

  const labelToks = tokens(h.label);
  const hasLure = labelToks.some((t) => LURE_WORDS.has(t));

  if (!BRAND_SET.has(h.label)) {
    // 1) brand + lure word in the domain: paypal-secure-login.com, appleidverify.com
    const brandTok = labelToks.find((t) => BRAND_SET.has(t) && !GENERIC_BRANDS.has(t)) ||
      gluedBrand(labelToks);
    if (brandTok && (hasLure || !labelToks.includes(brandTok)) && labelToks.join("") !== brandTok)
      add("brandlure", `Address combines "${brandTok}" with login/security words`, 40, { brand: brandTok, tier: "strong" });
    // 2) look-alike spelling: paypa1.com, amazom.com
    else {
      for (const t of labelToks) {
        const m = imitates(t, common);
        if (m) {
          add("lookalike", `Address imitates "${m.brand}" (${m.how})`, m.how === "misspelling" ? 15 : 40, { brand: m.brand, tier: m.how === "misspelling" ? "weak" : "strong" });
          break;
        }
      }
    }
  }

  // 3) brand hiding in a subdomain of an unrelated site: paypal.com.verify-acct.xyz
  const subToks = tokens(h.sub);
  const subBrand = subToks.find((t) => BRAND_SET.has(t) && t.length >= 3 && !GENERIC_BRANDS.has(t));
  if (subBrand && subBrand !== h.label && (subToks.some((t) => ["com", "net", "org", "ca"].includes(t)) || subToks.some((t) => LURE_WORDS.has(t))))
    add("subbrand", `"${subBrand}" appears in front of a different site's address`, 35, { brand: subBrand, tier: "strong" });

  if (h.sub.split(".").length >= 4) add("subs", "Unusually long chain of subdomains", 8);
  if (labelToks.length >= 4 && hasLure) add("hyphens", "Long hyphenated address with lure words", 8);

  return { h, flags };
}

// Scare / prize wording typical of phishing pages.
export const THREAT_RE = [
  /your account (has been|will be|is) (suspended|locked|limited|closed|disabled)/,
  /verify your (account|identity|information) (immediately|now|within)/,
  /unusual (sign-?in|login) activity/,
  /confirm your (billing|payment) (details|information)/,
  /congratulations.{0,60}(you('ve| have) won|winner|been selected)/,
];
// "We will NEVER ask you to verify your account immediately": a warning, not a threat.
const NEGATED = /\b(never|won['\u2019]t|will not|do not|don['\u2019]t|not)\s[^.]{0,40}$/;

// Page checks. Needs a DOM.
export function pageFlags(doc, loc) {
  const flags = [];
  const add = (id, label, weight, extra) => flags.push({ id, label, weight, tier: "weak", ...extra });
  const text = (doc.body?.innerText ?? doc.body?.textContent ?? "").toLowerCase();
  const title = (doc.title || "").toLowerCase();
  const here = parseHost(loc.hostname);
  const pageDomain = here.domain;
  const label = here.label || "";

  const pw = !!doc.querySelector('input[type="password"]');
  const card = !!doc.querySelector(
    'input[autocomplete^="cc-"], input[name*="cardnumber" i], input[name*="card_number" i], input[name*="card-number" i], input[name*="cvv" i], input[name*="cvc" i], input[id*="cardnumber" i]'
  );
  const sensitive = pw || card;

  const insecure = loc.protocol === "http:" && !isLoopback(loc.hostname);
  if (insecure && sensitive) add("http", "Asks for a password or card over an insecure connection", 35);
  else if (insecure) add("http", "Page is not served over HTTPS", 10);

  // Everything below only counts on pages that ask for a login or card,
  // so articles ABOUT scams, sales or crypto stay quiet.
  if (!sensitive) return { flags, sensitive, card };

  const links = [...doc.querySelectorAll("a")].map((a) => `${a.textContent} ${a.getAttribute("href") || ""}`.toLowerCase());
  if (!links.some((l) => /privacy|terms|policy|legal/.test(l)))
    add("nolegal", "Login/payment page with no privacy or terms link", 12);

  // Title opens with a brand the address doesn't belong to ("PayPal - Log In")
  for (const b of BRANDS) {
    if (b.length < 4 || label === b || label.includes(b)) continue;
    if (new RegExp(`^(?:(?:log ?in|sign ?in)\\s+(?:to\\s+)?)?${b}\\b`).test(title)) {
      add("brandmismatch", `Page says it's "${b}" but the address isn't ${b}'s`, 30, { brand: b, tier: "strong" });
      break;
    }
  }

  // Form posts to a different site
  const seen = new Set();
  doc.querySelectorAll("form[action]").forEach((f) => {
    try {
      const u = new URL(f.getAttribute("action"), loc.href);
      const d = parseHost(u.hostname).domain;
      if (d && d !== pageDomain && !seen.has(d)) {
        seen.add(d);
        add("xform", `Form sends your details to another site: ${d}`, 25, { target: d, tier: "strong" });
      }
    } catch {}
  });

  // Login/card form that posts over plain http from an https page.
  doc.querySelectorAll("form[action]").forEach((f) => {
    try {
      const u = new URL(f.getAttribute("action"), loc.href);
      if (u.protocol === "http:" && loc.protocol === "https:" && !isLoopback(u.hostname) && f.querySelector('input[type="password"], input[autocomplete^="cc-"]') && !flags.some((x) => x.id === "insecureform"))
        add("insecureform", "This form sends your details without encryption (plain http)", 35, { tier: "strong" });
    } catch {}
  });
  // Password form that explicitly says method=get. (No method attribute is not flagged: script-submitted forms often omit it.)
  if ([...doc.querySelectorAll("form")].some((f) => (f.getAttribute("method") || "").toLowerCase() === "get" && f.querySelector('input[type="password"]')))
    add("getlogin", "Password form puts the password in the web address", 12);
  // HTTPS page that pulls scripts over plain http.
  if (loc.protocol === "https:" && [...doc.querySelectorAll("script[src]")].some((s) => /^http:\/\//i.test(s.getAttribute("src")) && !isLoopback(new URL(s.getAttribute("src")).hostname)))
    add("mixed", "Secure page loads scripts over an insecure connection", 10);

  if (card) {
    const hasContact = /contact us|customer service|support@|help@|contact@/.test(text) ||
      !!doc.querySelector('a[href*="contact" i], a[href^="mailto:"], a[href^="tel:"]');
    if (!hasContact) add("nocontact", "Takes card details but lists no way to contact them", 12);
    if (!/refund|return policy|returns|cancellation/.test(text)) add("norefund", "Takes payment but has no refund/returns info", 6);
  }

  // Scare language: two or more patterns is strong, one is only a hint.
  const threat = THREAT_RE.filter((r) => {
    const m = r.exec(text);
    return m && !NEGATED.test(text.slice(Math.max(0, m.index - 45), m.index));
  }).length;
  if (threat >= 2) add("threat", "Scare / prize language typical of phishing", Math.min(10 + threat * 8, 30), { tier: "strong" });
  else if (threat === 1) add("threat", "Scare / prize language typical of phishing", 10);

  const pressure = [
    /only \d+ (left|remaining) in stock/, /act now/, /\d+ people (are )?(viewing|looking at) this/,
    /offer ends in \d/, /last chance/, /limited time only/,
  ].filter((r) => r.test(text)).length;
  if (pressure >= 2) add("pressure", `High-pressure sales tactics (${pressure} found)`, Math.min(pressure * 4, 12));

  if (/\b(8\d|9\d)% off\b/.test(text)) add("discount", "Unrealistically large discounts (80%+ off)", 10);

  if (/(pay|payment|accept|checkout).{0,40}(gift cards?|bitcoin|crypto|usdt|wire transfer|western union|moneygram)/.test(text))
    add("payment", "Asks for hard-to-refund payment (gift cards, crypto, wire)", 15);

  return { flags, sensitive, card };
}

// Runs in the page. Domain checks happen in the background (they need the word lists).
export function scan(doc, loc) {
  const { flags, sensitive, card } = pageFlags(doc, loc);
  return { host: loc.hostname, domain: parseHost(loc.hostname).domain, sensitive, card, flags };
}
