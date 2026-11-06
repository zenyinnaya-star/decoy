// Site security check: passive. Looks only at what the browser already has for THIS page (its HTML, and the headers the site sent).
// It never probes, guesses URLs, fuzzes, or sends attack strings. Findings are about the site's hygiene, NOT whether it is a scam:
// plenty of honest sites miss headers, so none of this feeds the scam score except where scanner.js already counts it.
// Each finding: { id, sev: high|medium|low|info, label, why, fix }

const loop = (h) => /^(localhost|127\.0\.0\.1|\[::1\])$/.test(h) || h.endsWith(".localhost");
const F = (id, sev, label, why, fix) => ({ id, sev, label, why, fix });

// Libraries whose version shows in the file name (jquery-1.12.4.min.js). "Looks like": the file name is a hint, not proof.
const LIBS = [
  { name: "jQuery", re: /jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, below: "3.5.0", why: "jQuery before 3.5.0 has known cross-site scripting (XSS) bugs." },
  { name: "AngularJS", re: /angular(?:\.min)?[-.]?(1\.\d+(?:\.\d+)?)/i, below: "99", why: "AngularJS 1.x reached end of life in 2022 and gets no security fixes." },
  { name: "Bootstrap", re: /bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.(?:js|css)/i, below: "3.4.1", why: "Bootstrap before 3.4.1 has known XSS bugs." },
  { name: "Lodash", re: /lodash[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, below: "4.17.21", why: "Lodash before 4.17.21 has known prototype-pollution and injection bugs." },
  { name: "Moment.js", re: /moment[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, below: "2.29.4", why: "Moment.js before 2.29.4 has a known denial-of-service bug." },
];
export const cmpVer = (a, b) => { const x = a.split(".").map(Number), y = b.split(".").map(Number); for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d < 0 ? -1 : 1; } return 0; };

// DOM + address findings. Pure: pass a document and a URL.
export function domFindings(doc, loc) {
  const out = [], https = loc.protocol === "https:", host = loc.hostname;
  const pw = !!doc.querySelector('input[type="password"]');
  const card = !!doc.querySelector('input[autocomplete^="cc-"], input[name*="cardnumber" i], input[name*="cvv" i]');
  const sensitive = pw || card;
  if (!https && !loop(host) && sensitive) out.push(F("login-http", "high", "Login or card form on an unencrypted page", "Anything typed here travels in the open and can be read by anyone on the same network.", "Don't enter details here. If this is your site: serve it over HTTPS."));
  else if (!https && !loop(host)) out.push(F("http", "medium", "Page isn't encrypted (http)", "Others on the network can read or change this page on its way to you.", "Use the https:// version if the site has one."));

  for (const f of doc.querySelectorAll("form")) {
    const method = (f.getAttribute("method") || "").toLowerCase(); // explicit only: forms with no method are often submitted by script
    if (method === "get" && f.querySelector('input[type="password"]'))
      out.push(F("get-password", "high", "Password form sends the password in the web address", "The password ends up in browser history, server logs and the Referer header.", "If this is your site: change the form to method=\"post\"."));
    try {
      const u = new URL(f.getAttribute("action") || "", loc.href);
      if (https && u.protocol === "http:" && !loop(u.hostname) && sensitive)
        out.push(F("form-http", "high", "Form sends details over plain http", "The page is secure but this form drops encryption.", "If this is your site: point the form at an https:// address."));
    } catch {}
  }
  if (https) {
    const active = [...doc.querySelectorAll("script[src], iframe[src], link[rel=stylesheet][href]")].filter((e) => /^http:\/\//i.test(e.getAttribute("src") || e.getAttribute("href") || ""));
    if (active.length) out.push(F("mixed-active", "high", `Secure page loads ${active.length} script/frame over http`, "An attacker on the network can swap that file and take over the page.", "If this is your site: load everything over https."));
    const passive = [...doc.querySelectorAll("img[src], audio[src], video[src]")].filter((e) => /^http:\/\//i.test(e.getAttribute("src") || ""));
    if (passive.length) out.push(F("mixed-passive", "low", `Secure page loads ${passive.length} image/media file(s) over http`, "Pictures can be swapped in transit. Less serious than scripts.", "Load them over https."));
  }
  const seen = new Set();
  for (const s of doc.querySelectorAll("script[src]")) {
    const src = s.getAttribute("src") || "";
    for (const L of LIBS) {
      const m = L.re.exec(src); if (!m || seen.has(L.name)) continue;
      if (cmpVer(m[1], L.below) < 0) { seen.add(L.name); out.push(F("old-" + L.name.toLowerCase(), "medium", `Looks like ${L.name} ${m[1]} (old)`, L.why + " (Guessed from the file name.)", `Update ${L.name}.`)); }
    }
  }
  const thirdNoSri = [...doc.querySelectorAll("script[src]")].filter((s) => { try { return new URL(s.src, loc.href).hostname !== host && !s.integrity; } catch { return false; } });
  if (thirdNoSri.length >= 3 && sensitive) out.push(F("no-sri", "low", `${thirdNoSri.length} outside scripts on a login/payment page with no integrity check`, "If one of those outside sites is hacked, its script runs on this page with access to what you type.", "If this is your site: add integrity (SRI) attributes or host the scripts yourself."));
  const q = loc.search.toLowerCase();
  if (/[?&](password|passwd|pwd|token|access_token|api_?key|secret|session(id)?)=/.test(q)) out.push(F("secret-in-url", "medium", "A password, token or key is in the web address", "Addresses are saved in history and logs and shared by accident.", "Don't share this link."));
  return out;
}

// Header findings. `h` is a lowercase-name -> value map of the response headers.
export function headerFindings(h, loc, sensitive = false) {
  const out = [], https = loc.protocol === "https:";
  const csp = h["content-security-policy"] || "";
  if (https && !h["strict-transport-security"]) out.push(F("no-hsts", "low", "No HSTS header", "Browsers can be tricked into using plain http on a first visit.", "Add Strict-Transport-Security."));
  if (!csp) out.push(F("no-csp", "low", "No Content-Security-Policy", "Nothing limits which scripts can run if the site has an injection bug.", "Add a Content-Security-Policy."));
  else if (/script-src[^;]*'unsafe-inline'/.test(csp) && !/'nonce-|'sha(256|384|512)-/.test(csp)) out.push(F("weak-csp", "info", "Content-Security-Policy allows inline scripts", "That weakens its protection against injected scripts.", "Use nonces or hashes instead of 'unsafe-inline'."));
  if (!h["x-frame-options"] && !/frame-ancestors/.test(csp)) out.push(F("no-frame", sensitive ? "medium" : "low", "Can be shown inside another site's frame", "Another page can overlay it invisibly and trick clicks (clickjacking)." + (sensitive ? " This page has a login or card form." : ""), "Add X-Frame-Options or CSP frame-ancestors."));
  if (!/nosniff/i.test(h["x-content-type-options"] || "")) out.push(F("no-nosniff", "info", "No X-Content-Type-Options: nosniff", "Browsers may guess file types, which can turn an upload into a script.", "Add X-Content-Type-Options: nosniff."));
  const server = (h["server"] || "") + " " + (h["x-powered-by"] || "");
  const m = /(apache\/2\.[0-2]\.|nginx\/1\.(?:[0-9]|1[0-5])\.|php\/[45]\.|iis\/[5-7]\.|openssl\/1\.0)/i.exec(server);
  if (m) out.push(F("old-server", "medium", `Server software looks very old (${m[1].replace(/\.$/, "")}…)`, "Old server versions have many known, public security holes.", "Update the server software."));
  else if (/\d+\.\d+/.test(server)) out.push(F("version-leak", "info", "Server announces its software version", "It helps an attacker pick the right known bug.", "Hide the version number."));
  return out;
}

const PTS = { high: 30, medium: 12, low: 4, info: 0 };
export function grade(findings) {
  const p = findings.reduce((n, f) => n + (PTS[f.sev] || 0), 0);
  const letter = p === 0 ? "A" : p <= 8 ? "B" : p <= 24 ? "C" : p <= 49 ? "D" : "F";
  return { letter, points: p };
}
export const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
