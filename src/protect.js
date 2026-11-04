// Content-script side of Decoy's protections. Top frame, document_idle.
// Auto-scan (A7), toasts, D1 interstitial, D5 overlays, D7/D8 payment-page scripts, D9 speed bump,
// D10 OAuth banner, D11 link check, D13 insecure form. Nothing here fills or submits anything for you.
import { scan } from "./scanner.js";
import { computeScore } from "./score.js";
import { GUARD_KINDS } from "./guard-rules.js";
import { classify } from "./destinations.js";
import { parseHost } from "./scanner.js";
import { BRAND_DOMAINS } from "./brand-domains.js";
import { linkMismatch } from "./links.js";
import { parseScopes } from "./oauth.js";
import { isGhostFrame, urlBarDomain, isReplayHost } from "./protect-rules.js";

const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);
const state = { testing: false, interstitial: null, extra: [], mode: "auto" };
export const setTesting = (b) => { state.testing = !!b; if (b) state.interstitial?.(); };

// ---- UI: one closed shadow host for toasts, banners and modals --------------------------------
let root, tray;
function ui() {
  if (root && root.host.isConnected) return root;
  const host = document.createElement("div");
  host.id = "decoy-protect-host";
  host.style.cssText = "all:initial;position:fixed;z-index:2147483646;top:0;left:0;width:0;height:0";
  root = host.attachShadow({ mode: "closed" });
  const st = document.createElement("style");
  st.textContent = `*{box-sizing:border-box}.tray{position:fixed;top:12px;right:12px;display:flex;flex-direction:column;gap:8px;width:min(340px,calc(100vw - 24px));font:13px/1.4 system-ui,sans-serif}
    .t{background:#fff;color:#1d1d1f;border-radius:10px;padding:10px 12px;box-shadow:0 6px 22px #0004;border:1px solid #ccc;border-left:6px solid var(--c,#1e8e3e)}
    .t b{display:block;font-size:14px;margin-bottom:2px}.t ul{margin:4px 0 0 16px;padding:0}.t .r{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
    button{font:inherit;padding:4px 10px;border:1px solid #888;border-radius:6px;background:#f3f3f3;color:#111;cursor:pointer}button.p{background:var(--c,#1e8e3e);border-color:var(--c,#1e8e3e);color:#fff}
    button[disabled]{opacity:.5;cursor:default}
    .bar{position:fixed;top:0;left:0;right:0;background:#fff4d6;color:#222;border-bottom:2px solid #e6a700;padding:8px 14px;font:13px/1.4 system-ui,sans-serif;display:flex;gap:12px;align-items:flex-start}
    .bar.bad{background:#ffe9e9;border-color:#d33}.bar ul{margin:2px 0 0 16px;padding:0}.bar button{margin-left:auto;flex:none}
    .wall{position:fixed;inset:0;background:#1b0b0bf2;display:flex;align-items:center;justify-content:center;font:15px/1.5 system-ui,sans-serif;padding:16px}
    .card{background:#fff;color:#1d1d1f;max-width:460px;width:100%;border-radius:14px;padding:22px 24px;border-top:8px solid #d33}
    .card h2{margin:0 0 8px;font-size:20px}.card .r{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.card button{padding:8px 14px;font-size:14px}
    .box{position:fixed;border:3px dashed #d33;background:#d332;pointer-events:none}`;
  tray = document.createElement("div"); tray.className = "tray";
  root.append(st, tray);
  (document.documentElement || document).append(host);
  return root;
}
const COLORS = { ok: "#1e8e3e", note: "#c9a100", warn: "#e8710a", bad: "#d33" };

function toast({ tone = "ok", title, lines = [], buttons = [], hideMs = 0 }) {
  ui();
  const el = document.createElement("div"); el.className = "t"; el.setAttribute("role", "alert"); el.style.setProperty("--c", COLORS[tone]);
  const b = document.createElement("b"); b.textContent = title; el.append(b);
  if (lines.length) { const ul = document.createElement("ul"); for (const l of lines) { const li = document.createElement("li"); li.textContent = l; ul.append(li); } el.append(ul); }
  const row = document.createElement("div"); row.className = "r";
  const done = () => el.remove();
  for (const [label, fn, primary] of buttons) {
    const x = document.createElement("button"); x.textContent = label; if (primary) x.className = "p";
    x.addEventListener("click", (e) => { if (!e.isTrusted) return; done(); try { fn && fn(); } catch {} }); row.append(x);
  }
  if (buttons.length) el.append(row);
  tray.append(el);
  if (hideMs) setTimeout(done, hideMs);
  return done;
}
function modal(card, wallClass = "wall") {
  const r = ui(); const w = document.createElement("div"); w.className = wallClass;
  card.setAttribute("role", "dialog"); card.setAttribute("aria-modal", "true");
  w.append(card); r.append(w);
  try { card.querySelector("button")?.focus(); } catch {}
  return () => w.remove();
}
const report = (kind) => { if (Object.hasOwn(GUARD_KINDS, kind)) { send({ type: "guard:event", kind }); if (!state.extra.includes(kind)) state.extra.push(kind); } };

// ---- D5 clickjacking + fake browser window ----------------------------------------------------
function detectOverlays(sensitive) {
  const hostDomain = parseHost(location.hostname).domain;
  for (const f of document.querySelectorAll("iframe")) {
    try {
      const cs = getComputedStyle(f), r = f.getBoundingClientRect();
      const cross = f.src && new URL(f.src, location.href).origin !== location.origin;
      if (isGhostFrame({ opacity: parseFloat(cs.opacity), visibility: cs.visibility, pointerEvents: cs.pointerEvents, position: cs.position, area: r.width * r.height, viewArea: innerWidth * innerHeight, crossOrigin: cross })) {
        report("clickjack");
        const box = document.createElement("div"); box.className = "box";
        box.style.cssText = `left:${r.left}px;top:${r.top}px;width:${r.width}px;height:${r.height}px`; ui().append(box);
        toast({ tone: "bad", title: "Invisible layer over this page", lines: ["Something transparent is on top, so your clicks may land on a different site. It is outlined in red."], buttons: [["Close this tab", () => send({ type: "guard:close" }), true], ["Dismiss"]] });
        break;
      }
    } catch {}
  }
  if (!document.querySelector('input[type="password"]')) return;
  let n = 0;
  for (const el of document.querySelectorAll("div,span,p")) {
    if (++n > 1500) break;
    if (el.children.length) continue;
    const d = urlBarDomain(el.textContent);
    if (!d || parseHost(d).domain === hostDomain) continue;
    let c = el;
    for (let i = 0; i < 7 && c.parentElement; i++, c = c.parentElement) {
      if (!c.querySelector('input[type="password"]')) continue;
      const pos = getComputedStyle(c).position;
      if (pos === "fixed" || pos === "absolute" || c.parentElement === document.body) {
        report("bitb");
        toast({ tone: "bad", title: "This 'window' is part of the web page", lines: [`The address bar showing ${d} is just a picture drawn by the page. Don't type your password here.`], buttons: [["Close this tab", () => send({ type: "guard:close" }), true], ["Dismiss"]] });
        return;
      }
    }
  }
}

// ---- D7 / D8 payment-page scripts, session replay ----------------------------------------------
function scriptsOnSensitive(card) {
  const bad = new Set(); let replay = false;
  for (const s of document.scripts) {
    if (!s.src) continue;
    let u; try { u = new URL(s.src, location.href); } catch { continue; }
    const k = classify(u.href, location.hostname);
    if (k.kind === "grabber" || k.kind === "suspicious") bad.add(u.hostname);
    if (isReplayHost(u.hostname)) replay = true;
  }
  if (card && bad.size) report("skim-host");
  if (replay) report("replay");
  return [...bad];
}

// ---- D11 links that say one thing and go to another ---------------------------------------------
function checkLinks(sensitive) {
  let n = 0;
  for (const a of document.querySelectorAll("a[href]")) {
    if (++n > 500) break;
    const m = linkMismatch(a.textContent, a.href, location.hostname, { sensitive });
    if (!m) continue;
    a.style.outline = "2px dashed #d33"; a.title = `Shows ${m.shown} but goes to ${m.actual}`;
    report(sensitive ? "link-mismatch-login" : "link-mismatch");
  }
}

// ---- D10 OAuth consent -------------------------------------------------------------------------
function oauthBanner() {
  const p = parseScopes(location.href);
  if (!p || !p.scopes.length) return false;
  const risky = p.scopes.filter((s) => s.broad);
  if (!risky.length) return false;
  const unverified = /hasn.?t verified|unverified app|not verified/i.test(document.body?.innerText || "");
  report(unverified ? "oauth-broad-unverified" : "oauth-broad");
  const r = ui(); const bar = document.createElement("div"); bar.className = "bar" + (unverified ? " bad" : ""); bar.setAttribute("role", "alert");
  const box = document.createElement("div");
  const h = document.createElement("b"); h.textContent = `${unverified ? "Unverified app: " : ""}This app is asking for a lot of access to your ${p.provider} account`;
  const ul = document.createElement("ul"); for (const s of risky) { const li = document.createElement("li"); li.textContent = s.plain; ul.append(li); }
  const note = document.createElement("div"); note.textContent = "If you didn't start this yourself, click Cancel on the page.";
  box.append(h, ul, note);
  const x = document.createElement("button"); x.textContent = "Dismiss"; x.onclick = (e) => { if (e.isTrusted) bar.remove(); };
  bar.append(box, x); r.append(bar);
  return true;
}

// ---- D1 look-alike interstitial ------------------------------------------------------------------
const BRAND_IDS = new Set(["brandlure", "lookalike", "subbrand", "punycode", "brandmismatch"]);
function interstitial(brand, flags) {
  const real = BRAND_DOMAINS[brand];
  const card = document.createElement("div"); card.className = "card";
  const h = document.createElement("h2"); h.textContent = real ? `This looks like ${real}, but it isn't` : `This page imitates "${brand}"`;
  const p = document.createElement("p"); p.textContent = `You're on ${location.hostname}, and it asks for a login or card. ${flags[0]?.label || ""}`;
  const row = document.createElement("div"); row.className = "r";
  let gone;
  const btn = (label, fn, primary) => { const b = document.createElement("button"); b.textContent = label; if (primary) b.style.cssText = "background:#d33;color:#fff;border-color:#d33"; b.addEventListener("click", (e) => { if (e.isTrusted) fn(); }); row.append(b); };
  if (real) btn(`Go to ${real}`, () => { location.href = `https://${real}/`; }, true);
  btn("Close this tab", () => send({ type: "guard:close" }), !real);
  btn("Allow this once", () => gone());
  card.append(h, p, row);
  gone = modal(card);
  state.interstitial = gone;
}

// ---- D9 submit speed bump ------------------------------------------------------------------------
function speedBump() {
  const ok = new WeakSet();
  document.addEventListener("submit", (e) => {
    const f = e.target;
    if (state.testing || ok.has(f) || !e.isTrusted || !f.querySelector?.('input[type="password"], input[autocomplete^="cc-"]')) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const card = document.createElement("div"); card.className = "card";
    const h = document.createElement("h2"); h.textContent = "Wait. This page looks risky.";
    const p = document.createElement("p"); p.textContent = "Decoy found strong warning signs here. If you send this, the details go to whoever runs this page.";
    const row = document.createElement("div"); row.className = "r";
    const back = document.createElement("button"); back.textContent = "Go back"; back.style.cssText = "background:#d33;color:#fff;border-color:#d33";
    const go = document.createElement("button"); go.disabled = true;
    let n = 3; go.textContent = `Submit anyway (${n})`;
    const t = setInterval(() => { n--; if (n <= 0) { clearInterval(t); go.disabled = false; go.textContent = "Submit anyway"; } else go.textContent = `Submit anyway (${n})`; }, 1000);
    let gone;
    back.addEventListener("click", (ev) => { if (ev.isTrusted) { clearInterval(t); gone(); } });
    go.addEventListener("click", (ev) => { if (!ev.isTrusted || go.disabled) return; gone(); ok.add(f); send({ type: "cloud:entered" }); try { f.requestSubmit(e.submitter || undefined); } catch { f.submit(); } });
    row.append(back, go); card.append(h, p, row); gone = modal(card);
  }, true);
}

// ---- D13 typing a password on an unencrypted page ------------------------------------------------
function insecureWatch(flags) {
  if (!flags.some((f) => f.id === "http" || f.id === "insecureform")) return;
  document.addEventListener("focusin", (e) => {
    if (e.target?.type !== "password") return;
    toast({ tone: "bad", title: "Not encrypted", lines: ["Anything typed here can be read by others on the network. Don't enter your real password."], buttons: [["Dismiss"]] });
  }, { once: true });
}

// ---- the orchestrator ---------------------------------------------------------------------------
const flagsOf = (res, extra) => [...res.flags, ...extra.filter((k) => Object.hasOwn(GUARD_KINDS, k)).map((k) => ({ id: k, ...GUARD_KINDS[k] }))];
const lines = (r, n = 3) => r.flags.filter((f) => f.weight > 0).slice(0, n).map((f) => f.label);

async function runScan({ manual = false } = {}) {
  const s = scan(document, location);
  const settings = await chrome.storage.local.get(["off", "paused"]);
  const off = settings.off || {};
  if ((settings.paused || []).includes(s.domain || s.host)) { send({ type: "badge", paused: true }); return; } // you paused Decoy here
  const res = await send({ type: "assess", scan: s, quick: true });
  if (!res) return;
  detectOverlays(s.sensitive); setTimeout(() => detectOverlays(s.sensitive), 1500);
  const hosts = scriptsOnSensitive(s.card);
  if (!off.links) checkLinks(s.sensitive);
  const oauth = oauthBanner();
  const r = computeScore(flagsOf(res, state.extra), { trustKind: res.trustKind });
  send({ type: "badge", score: r.score, trustKind: res.trustKind });
  insecureWatch(res.flags);

  const { muted = [] } = await chrome.storage.local.get("muted");
  const isMuted = muted.includes(s.domain || s.host);

  // D1: a strong brand-imitation flag on a login/card page gets a full-page stop.
  const brandFlag = res.flags.find((f) => BRAND_IDS.has(f.id) && f.brand && f.tier === "strong");
  if (brandFlag && s.sensitive && !state.testing && res.trustKind !== "you") { interstitial(brandFlag.brand, res.flags); }

  // D9
  if (s.sensitive && r.strong >= 1 && r.score >= 45 && !off.bump) speedBump();

  if (oauth || state.interstitial && r.score >= 70) return; // those already say it
  if (isMuted && r.score < 70) return;
  const bad = r.score >= 70, mid = r.score >= 45, low = r.score >= 45; // below 45 the badge says it; no pop-up for small stuff
  if (low) {
    toast({
      tone: bad ? "bad" : mid ? "warn" : "note",
      title: bad ? "Warning signs found on this page" : mid ? "Be careful on this page" : "A few things look off",
      lines: [...lines(r), ...(hosts.length ? [`Payment page loads a script from ${hosts[0]}`] : [])],
      buttons: [["Dismiss", null, bad], ["Don't tell me about this site", () => chrome.storage.local.set({ muted: [...muted, s.domain || s.host] })]],
      hideMs: bad ? 0 : 12000,
    });
  } else if (r.score >= 20 && (s.sensitive || manual)) {
    toast({ tone: "note", title: "A few small things look off", lines: lines(r, 2), hideMs: 6000 });
  } else if (s.sensitive || manual) {
    toast({ tone: "ok", title: res.trustKind ? "Checked: well-known site" : "Checked in the background: looks fine", lines: [], hideMs: 4000 });
  }
}

export async function start() {
  const { mode = "auto", paused = [] } = await chrome.storage.local.get(["mode", "paused"]);
  if (paused.includes(parseHost(location.hostname).domain || location.hostname)) { send({ type: "badge", paused: true }); return; }
  state.mode = mode;
  if (mode === "off") return;
  const s = scan(document, location);
  const { muted = [] } = await chrome.storage.local.get("muted");
  if (mode === "ask" && s.sensitive && !muted.includes(s.domain || s.host)) {
    toast({
      tone: "note", title: "This page asks for a password or card",
      lines: ["Want Decoy to scan it for scam signs?"],
      buttons: [["Scan now", () => runScan({ manual: true }), true], ["Not now"], ["Don't ask for this site", () => chrome.storage.local.set({ muted: [...muted, s.domain || s.host] })]],
    });
    return;
  }
  if (mode === "ask") { runScan().catch(() => {}); return; } // quiet: badge only
  runScan().catch(() => {});
}

// ---- messages from the background -----------------------------------------------------------------
export const notice = (n) => toast({ tone: n.tone, title: n.title, lines: n.lines || [], buttons: [["Dismiss"]], hideMs: n.hideMs || 0 });

// D4: the background paused a download from an unfamiliar site.
export function askDownload(m) {
  let mine = false;
  try { mine = m.referrer ? new URL(m.referrer).hostname === location.hostname : document.visibilityState === "visible"; } catch {}
  if (!mine) return false;
  report("download-exec");
  toast({ tone: "bad", title: "Decoy paused a download", lines: [`${m.name} is a program file from ${m.host}. Only keep it if you went looking for it.`],
    buttons: [["Cancel download", () => send({ type: "dl:cancel", id: m.id }), true], ["Keep it", () => send({ type: "dl:keep", id: m.id })]] });
  return true;
}

// The finished download was checked: tell the person, in plain English.
export function showDownloadResult(m) {
  let mine = false;
  try { mine = m.referrer ? new URL(m.referrer).hostname === location.hostname : document.visibilityState === "visible"; } catch {}
  if (!mine) return false;
  const bad = m.verdict === "problem", care = m.verdict === "careful";
  if (bad) report("download-flagged");
  const del = ["Delete the file", () => send({ type: "dl:delete", id: m.id }), bad];
  toast({
    tone: bad ? "bad" : care ? "warn" : "ok",
    title: bad ? `Problem: ${m.name}` : care ? `Be careful: ${m.name}` : `Checked: ${m.name}`,
    lines: m.verdict === "nothing"
      ? ["Nothing suspicious found. That is not a guarantee the file is safe.", ...(m.limited ? ["Only the name and source were checked. Turn on \"Allow access to file URLs\" for Decoy to look inside."] : [])]
      : [...m.reasons, ...(m.limited ? ["(Name and source only. Allow file URL access for Decoy to look inside.)"] : [])],
    buttons: bad || care ? [del, ["Dismiss"]] : [["Dismiss"]],
    hideMs: bad || care ? 0 : 9000,
  });
  return true;
}
