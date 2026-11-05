import { GUARD_KINDS } from "./guard-rules.js";
import ALLOW from "./allowlist.json";
import WORDS from "./common-words.json";
import { assess } from "./assess.js";
import { domainFlags } from "./scanner.js";
import { matchNeedles } from "./match.js";
import { buildVerdict } from "./verdict.js";
import { computeScore } from "./score.js";
import { isShortener } from "./links.js";
import { extractUrls, textFlags } from "./precheck.js";
import { parseHost } from "./scanner.js";
import { isInstitution } from "./trust.js";
import { badgeFor } from "./protect-rules.js";
import { analyze, sha256hex } from "./filecheck.js";
import { make } from "./flags.js";
import * as cloud from "./cloud.js";

const common = new Set(WORDS);
const allow = new Set(ALLOW);
const TTL = 7 * 24 * 3600 * 1000;

async function userAllowed() {
  return new Set((await chrome.storage.local.get("trusted")).trusted || []);
}

// Cache only: the automatic background scan never makes a network request.
async function cachedAgeDays(domain) {
  const key = `age:${domain}`;
  const c = (await chrome.storage.local.get(key))[key];
  return c ? c.days : null;
}

async function domainAgeDays(domain) {
  const key = `age:${domain}`;
  const cached = (await chrome.storage.local.get(key))[key];
  if (cached && Date.now() - cached.t < TTL) return cached.days;
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`);
    if (!res.ok) throw new Error(res.status);
    const data = await res.json();
    const reg = data.events?.find((e) => e.eventAction === "registration")?.eventDate;
    if (!reg) throw new Error("no registration date");
    const days = Math.floor((Date.now() - new Date(reg).getTime()) / 86400000);
    await chrome.storage.local.set({ [key]: { days, t: Date.now() } });
    return days;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// Dummy test state: one per tab, kept in session storage (gone when the browser closes).
// Holds the fake values to look for; never anything real.
// ---------------------------------------------------------------------------------------------
const TEST_TTL = 30 * 60 * 1000;
const sKey = (t) => `dummy:${t}`;
const loadState = async (t) => {
  const s = (await chrome.storage.session.get(sKey(t)))[sKey(t)] || null;
  if (s && Date.now() - s.startedAt > TEST_TTL) { await chrome.storage.session.remove(sKey(t)); return null; }
  return s;
};
const saveState = (t, s) => chrome.storage.session.set({ [sKey(t)]: s });

// Messages arrive in bursts; update one tab's state strictly one at a time.
const chains = new Map();
function locked(tabId, fn) {
  const run = (chains.get(tabId) || Promise.resolve()).then(fn, fn);
  chains.set(tabId, run.catch(() => {}));
  return run;
}

const KINDS = new Set(["email", "password", "phone", "card"]);
const ENCS = new Set(["plain", "url", "base64", "hex", "sha256", "sha1", "md5"]);
const VIAS = new Set(["fetch", "xhr", "beacon", "websocket", "pixel", "form", "url"]);

// Page scripts can fire the hit event too, so treat it as untrusted input.
function cleanHit(h) {
  if (!h || typeof h.url !== "string") return null;
  const hits = (Array.isArray(h.hits) ? h.hits : [])
    .filter((x) => KINDS.has(x?.kind) && ENCS.has(x?.enc)).slice(0, 20).map((x) => ({ kind: x.kind, enc: x.enc }));
  if (!hits.length) return null;
  let url;
  try { const u = new URL(h.url); url = u.origin + u.pathname; } catch { return null; } // drop the query: it may hold the values
  return { url: url.slice(0, 500), via: VIAS.has(h.via) ? h.via : "fetch", hits, beforeSubmit: !!h.beforeSubmit };
}

const broadcast = (tabId, msg) => chrome.tabs.sendMessage(tabId, msg).catch(() => {});

function handleDummy(msg, sender, reply) {
  // Content scripts are identified by their tab. The popup (an extension page) names the tab it is looking at.
  const fromExtensionPage = !!sender.url && sender.url.startsWith(chrome.runtime.getURL(""));
  const tabId = fromExtensionPage ? msg.tabId : sender.tab?.id;
  if (tabId == null) { reply(null); return; }

  switch (msg.type) {
    case "dummy:hello":
      locked(tabId, async () => {
        const s = await loadState(tabId);
        reply(s ? { armed: true, needles: s.needles, submitted: s.submitted } : { armed: false });
      });
      return;

    case "dummy:arm":
      locked(tabId, async () => {
        const needles = (Array.isArray(msg.needles) ? msg.needles : []).slice(0, 60)
          .filter((n) => KINDS.has(n?.kind) && ENCS.has(n?.enc) && typeof n.text === "string");
        const s = {
          host: String(msg.host || ""), needles, submitted: false, hadPassword: !!msg.hadPassword,
          findings: [], pages: [], startedAt: Date.now(),
        };
        await saveState(tabId, s);
        broadcast(tabId, { type: "dummy:needles", needles, submitted: false });
        reply({ ok: true });
      });
      return;

    case "dummy:hit":
      locked(tabId, async () => {
        const s = await loadState(tabId);
        if (!s) return reply(null);
        if (msg.hit?.type === "submit") {
          if (!s.submitted) { s.submitted = true; await saveState(tabId, s); }
        } else {
          const f = cleanHit(msg.hit);
          if (f) {
            f.beforeSubmit = f.beforeSubmit && !s.submitted; // the background's view of "submitted" wins across frames
            if (s.findings.length < 300) s.findings.push(f);
            await saveState(tabId, s);
          }
        }
        reply(null);
      });
      return;

    case "dummy:page":
      locked(tabId, async () => {
        const s = await loadState(tabId);
        if (!s) return reply(null);
        const host = String(msg.host || "").slice(0, 253);
        const extraAsk = (Array.isArray(msg.extraAsk) ? msg.extraAsk : []).filter((x) => typeof x === "string").slice(0, 6).map((x) => x.slice(0, 60));
        if (s.pages.length < 30) s.pages.push({ host, afterSubmit: s.submitted, extraAsk });
        // Did the dummy values end up in the address bar or the referrer?
        for (const [where, text] of [["url", msg.href], ["referrer", msg.referrer]]) {
          const hits = typeof text === "string" ? matchNeedles(text, s.needles) : [];
          if (hits.length && s.findings.length < 300) {
            try { const u = new URL(text); s.findings.push({ url: u.origin + u.pathname, via: "url", hits, beforeSubmit: false }); } catch {}
          }
        }
        await saveState(tabId, s);
        reply(null);
      });
      return;

    case "dummy:state":
      locked(tabId, async () => {
        const s = await loadState(tabId);
        if (!s) { reply({ armed: false }); return; }
        const verdict = buildVerdict(s, { pageScore: Number(msg.pageScore) || 0 });
        reply({ armed: true, host: s.host, verdict });
        // Opt-in: a confirmed grabber helps everyone else. Domain + finding type only, and never for trusted sites.
        if (verdict.status === "grabber" && !s.shared) {
          s.shared = true; await saveState(tabId, s);
          const domain = parseHost(s.host).domain || s.host;
          const mine = await userAllowed();
          if (domain && !allow.has(domain) && !mine.has(domain) && !isInstitution(parseHost(domain).suffix)) cloud.reportFindings(domain, cloud.findingTypes(verdict.items));
        }
      });
      return;

    case "dummy:stop":
      locked(tabId, async () => {
        await chrome.storage.session.remove(sKey(tabId));
        broadcast(tabId, { type: "dummy:disarm" });
        reply({ ok: true });
      });
      return;
  }
}

chrome.tabs.onRemoved.addListener((tabId) => { chrome.storage.session.remove(sKey(tabId)); });

// ---------------------------------------------------------------------------------------------

// ---- active guards: per-tab list of kinds that fired (kind + count only; no page data) ----
const gKey = (t) => `g:${t}`;
let gLock = Promise.resolve();
chrome.tabs.onRemoved.addListener((t) => chrome.storage.session.remove(gKey(t)));
chrome.tabs.onUpdated.addListener((t, info) => { if (info.status === "loading" && info.url !== undefined) chrome.storage.session.remove(gKey(t)); });

chrome.runtime.onMessage.addListener((msg, sender, send) => {
  if (msg?.type === "guard:event") {
    const t = sender.tab?.id;
    if (t != null && Object.hasOwn(GUARD_KINDS, msg.kind)) {
      gLock = gLock.then(async () => {
        const cur = (await chrome.storage.session.get(gKey(t)))[gKey(t)] || {};
        cur[msg.kind] = Math.min((cur[msg.kind] || 0) + 1, 99);
        await chrome.storage.session.set({ [gKey(t)]: cur });
      }).catch(() => {});
    }
    return;
  }
  if (msg?.type === "guard:close") { if (sender.tab?.id != null) chrome.tabs.remove(sender.tab.id).catch(() => {}); return; }
  if (msg?.type === "guard:state") {
    (async () => {
      const cur = (await chrome.storage.session.get(gKey(msg.tabId)))[gKey(msg.tabId)] || {};
      send(Object.entries(cur).filter(([k]) => Object.hasOwn(GUARD_KINDS, k)).map(([k, n]) => ({ id: k, n, ...GUARD_KINDS[k] })));
    })();
    return true;
  }
  if (msg?.type?.startsWith("dummy:")) { handleDummy(msg, sender, send); return true; }

  if (msg?.type === "assess") {
    (async () => {
      const mine = await userAllowed();
      const isTrusted = (d) => allow.has(d) || mine.has(d);
      const s = { ...msg.scan, flags: [...domainFlags(msg.scan.host, common).flags, ...msg.scan.flags] };
      const ageDays = s.domain && !isTrusted(s.domain) ? (msg.quick || !(await chrome.storage.local.get("ageLookup")).ageLookup ? await cachedAgeDays(s.domain) : await domainAgeDays(s.domain)) : null;
      const out = assess(s, { isTrusted, isUserTrusted: (d) => mine.has(d), ageDays });
      // Confirmed by several other people's dummy tests? That is real evidence, but never against a site you or the top list trust.
      if (!out.trustKind && (await cloud.onSharedList(s.domain))) out.flags.push(make("crowd"));
      send({ ...out, userTrusted: mine.has(s.domain) });
    })();
    return true;
  }
  if (msg?.type === "trust") {
    (async () => {
      const mine = await userAllowed();
      msg.on ? mine.add(msg.domain) : mine.delete(msg.domain);
      await chrome.storage.local.set({ trusted: [...mine] });
      send({ ok: true });
    })();
    return true;
  }
});


// =============================================================================================
// Phase D extras: badge, link check, pre-check, downloads, recovery reminder, tracker blocking
// =============================================================================================
chrome.runtime.onMessage.addListener((msg, sender, send) => {
  if (msg?.type === "guard:config") {
    (async () => {
      let host = ""; try { host = new URL(sender.url).hostname; } catch {}
      const domain = parseHost(host).domain || host;
      const { paused = [], off = {} } = await chrome.storage.local.get(["paused", "off"]);
      const mine = await userAllowed();
      const trusted = !!domain && (mine.has(domain) || allow.has(domain) || isInstitution(parseHost(domain).suffix));
      send({ paused: paused.includes(domain), off, trusted });
    })();
    return true;
  }
  if (msg?.type === "cloud:entered" && sender.tab?.url) {
    try { const h = new URL(sender.tab.url).hostname; cloud.alertGuardians("entered", parseHost(h).domain || h, true); } catch {}
    return;
  }
  if (msg?.type === "cloud:sync") { cloud.syncList().then((ok) => send({ ok })).catch((e) => send({ ok: false, error: e.message })); return true; }
  if (msg?.type === "badge" && sender.tab?.id != null) {
    // A very risky page you stay on for 30 seconds is worth telling your trusted people about.
    if (!msg.paused && Number(msg.score) >= 70 && !msg.trustKind) {
      try { const h = new URL(sender.tab.url).hostname; chrome.storage.session.set({ [`likely:${sender.tab.id}`]: parseHost(h).domain || h }); chrome.alarms.create(`decoy-likely:${sender.tab.id}`, { delayInMinutes: 0.5 }); } catch {}
    }
    const b = msg.paused ? { text: "II", color: "#777" } : badgeFor(Number(msg.score) || 0, msg.trustKind || null);
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: b.text }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: b.color }).catch(() => {});
    return;
  }
  if (msg?.type === "precheck") { precheck(String(msg.text || "").slice(0, 5000)).then(send); return true; }
  if (msg?.type === "recovery:remind") {
    chrome.alarms.create("decoy-recovery", { delayInMinutes: 24 * 60 });
    send({ ok: true }); return;
  }
  if (msg?.type === "ads:get") { chrome.storage.local.get("adblock").then((r) => send({ on: !!r.adblock })); return true; }
  if (msg?.type === "ads:set") {
    (async () => {
      const on = !!msg.on;
      const { off = {} } = await chrome.storage.local.get("off");
      off.adblock = !on; // false = explicitly on (default-off feature, see ctx.opt)
      await chrome.storage.local.set({ adblock: on, off });
      await chrome.declarativeNetRequest.updateEnabledRulesets(on ? { enableRulesetIds: ["ads"] } : { disableRulesetIds: ["ads"] });
      send({ on });
    })();
    return true;
  }
  if (msg?.type === "trackers:get") { chrome.declarativeNetRequest.getEnabledRulesets().then((r) => send({ on: r.includes("trackers") })); return true; }
  if (msg?.type === "trackers:set") {
    chrome.declarativeNetRequest.updateEnabledRulesets(msg.on ? { enableRulesetIds: ["trackers"] } : { disableRulesetIds: ["trackers"] }).then(() => send({ on: !!msg.on }));
    return true;
  }
  if (msg?.type === "dl:cancel" && chrome.downloads) {
    (async () => { try { await chrome.downloads.cancel(msg.id); } catch {} try { await chrome.downloads.removeFile(msg.id); } catch {} try { await chrome.downloads.erase({ id: msg.id }); } catch {} send({ ok: true }); })();
    return true;
  }
  if (msg?.type === "dl:keep" && chrome.downloads) { chrome.downloads.resume(msg.id).catch(() => {}); send({ ok: true }); return; }
});

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === "decoy-cloud-sync") { cloud.syncList().catch(() => {}); return; }
  if (a.name.startsWith("decoy-likely:")) {
    const id = Number(a.name.split(":")[1]), key = `likely:${id}`;
    const domain = (await chrome.storage.session.get(key))[key];
    await chrome.storage.session.remove(key);
    try { const t = await chrome.tabs.get(id); const h = new URL(t.url).hostname; if (domain && (parseHost(h).domain || h) === domain) cloud.alertGuardians("likely", domain, false); } catch {}
    return;
  }
  if (a.name === "decoy-recovery" && chrome.notifications)
    chrome.notifications.create("decoy-recovery", { type: "basic", iconUrl: "icon128.png", title: "Decoy reminder", message: "Yesterday you said you entered details on a risky page. Did you change the password and call your bank?" });
});

chrome.alarms.create("decoy-cloud-sync", { delayInMinutes: 1, periodInMinutes: 12 * 60 }); // does nothing unless you turned the shared list on
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => chrome.contextMenus.create({ id: "decoy-link", title: "Check this link with Decoy", contexts: ["link"] }));
});
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "decoy-link" || !tab?.id) return;
  const r = await precheck(info.linkUrl || "");
  chrome.tabs.sendMessage(tab.id, { type: "decoy:notice", notice: { tone: r.score >= 70 ? "bad" : r.score >= 45 ? "warn" : r.score >= 20 ? "note" : "ok", title: `Link check: ${r.level}`, lines: [r.items[0]?.host || "", ...r.reasons.slice(0, 3)].filter(Boolean), hideMs: r.score >= 45 ? 0 : 8000 } }, { frameId: 0 }).catch(() => {});
});

// ---- judge a URL without opening it ----
async function judgeUrl(urlStr, bare) {
  let u; try { u = new URL(urlStr); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase();
  const df = domainFlags(host, common);
  let flags = [...df.flags];
  const mine = await userAllowed();
  const domain = df.h.domain;
  const trustKind = domain && (mine.has(domain) ? "you" : isInstitution(parseHost(domain).suffix) ? "institution" : allow.has(domain) ? "popular" : null);
  if (trustKind) flags = [];
  if (u.username || u.password) flags.push({ id: "userinfo", label: "Address hides the real site behind a name@ trick", weight: 30, tier: "strong" });
  if (isShortener(host)) flags.push({ id: "short", label: "Shortened link: the real destination is hidden", weight: 12, tier: "weak" });
  if (!bare && u.protocol === "http:") flags.push({ id: "http", label: "Link is not encrypted (http)", weight: 8, tier: "weak" });
  return { host, domain, trustKind, flags };
}

async function precheck(text) {
  const urls = (await Promise.all(extractUrls(text).map((x) => judgeUrl(x.url, x.bare)))).filter(Boolean);
  const tf = textFlags(text);
  const all = [...urls.flatMap((x) => x.flags), ...tf];
  const onlyTrusted = urls.length > 0 && urls.every((x) => x.trustKind);
  const r = computeScore(all, { trustKind: onlyTrusted && !tf.length ? "popular" : null });
  const items = urls.map((x) => {
    const s = computeScore(x.flags, { trustKind: x.trustKind });
    return { host: x.host, level: s.level, color: s.color, reasons: s.flags.map((f) => f.label) };
  });
  return { score: r.score, level: r.level, color: r.color, sub: r.sub, items, reasons: r.flags.map((f) => f.label), hadUrls: urls.length > 0 };
}

// ---- D4: programs from unfamiliar sites are paused until you decide ----
const EXEC = /\.(exe|msi|scr|bat|cmd|ps1|lnk|jse?|vbe?|hta|iso|dmg|pkg|apk|jar|com|pif|appx|msix)(?:$|[?#])/i;
let dlHooked = false;
function initDownloads() {
  if (dlHooked || !chrome.downloads?.onCreated) return; // permission not granted (yet)
  dlHooked = true;
  chrome.downloads.onCreated.addListener(onDownload);
  chrome.downloads.onChanged.addListener((d) => { if (d.state?.current === "complete") checkFinished(d.id); });
}
chrome.permissions.onAdded.addListener(initDownloads);
initDownloads();
async function onDownload(item) {
  try {
    const url = item.finalUrl || item.url || "";
    const name = (item.filename || "").split(/[\\/]/).pop() || decodeURIComponent(new URL(url).pathname.split("/").pop() || "file");
    if (!EXEC.test(item.filename || "") && !EXEC.test(new URL(url).pathname)) return;
    const host = new URL(url).hostname.toLowerCase();
    const domain = parseHost(host).domain || host;
    const mine = await userAllowed();
    if (allow.has(domain) || mine.has(domain) || isInstitution(parseHost(host).suffix)) return;
    await chrome.downloads.pause(item.id).catch(() => {});
    const tabs = await chrome.tabs.query({});
    const replies = await Promise.all(tabs.map((t) => chrome.tabs.sendMessage(t.id, { type: "dl:ask", id: item.id, name, host, referrer: item.referrer || "" }, { frameId: 0 }).catch(() => null)));
    if (!replies.some((r) => r?.shown)) chrome.downloads.resume(item.id).catch(() => {}); // nobody to ask: don't hold it hostage
  } catch {}
}



// ---- Download check: look at a finished download and say "problem", "be careful" or "nothing suspicious found" ----
const HEAD_BYTES = 2 * 1024 * 1024, TAIL_BYTES = 256 * 1024, HASH_MAX = 64 * 1024 * 1024;
const baseName = (p) => String(p || "").split(/[\\/]/).pop();
const niceName = (item) => {
  const f = baseName(item.filename);
  if (/^[0-9a-f-]{32,36}$/i.test(f)) { try { return decodeURIComponent(baseName(new URL(item.finalUrl || item.url).pathname)) || f; } catch {} } // test harness stores files under random names
  return f || "file";
};

async function fileAccess() { try { return await chrome.extension.isAllowedFileSchemeAccess(); } catch { return false; } }

// Read the first/last bytes of the finished file. Needs "Allow access to file URLs" for Decoy.
async function readFile(item, name) {
  let url = "file:///" + String(item.filename).replace(/\\/g, "/").split("/").map((s, i) => (i === 0 && /^[A-Za-z]:$/.test(s) ? s : encodeURIComponent(s))).join("/");
  if (__TEST__) { const { testReadBase } = await chrome.storage.local.get("testReadBase"); if (testReadBase) url = testReadBase + encodeURIComponent(name); }
  const res = await fetch(url);
  if (!res.ok && res.status !== 0) throw new Error("read failed");
  const all = new Uint8Array(await res.arrayBuffer()); // capped below
  const size = all.length;
  return { head: all.subarray(0, Math.min(size, HEAD_BYTES)), tail: size > HEAD_BYTES ? all.subarray(size - TAIL_BYTES) : null, size, hashable: size <= HASH_MAX ? all : null };
}

async function checkFinished(id) {
  try {
    const { off = {} } = await chrome.storage.local.get("off");
    if (off.dlscan) return;
    const [item] = await chrome.downloads.search({ id });
    if (!item || item.state !== "complete" || !item.filename) return;
    const url = item.finalUrl || item.url || "";
    let host = ""; try { host = new URL(url).hostname.toLowerCase(); } catch {}
    const name = niceName(item);
    const domain = parseHost(host).domain || host;
    const mine = await userAllowed();
    const trusted = !!domain && (allow.has(domain) || mine.has(domain) || isInstitution(parseHost(host).suffix));
    const flagged = !trusted && host && domainFlags(host, common).flags.some((f) => f.tier === "strong");

    let data = null;
    if (__TEST__ || (await fileAccess())) { try { data = await readFile(item, name); } catch {} }
    const r = analyze({ name, head: data?.head || null, tail: data?.tail || null, size: data?.size || item.fileSize || 0, source: { host, trusted, flagged } });
    const sha = data?.hashable ? await sha256hex(data.hashable) : null;

    const rec = { t: Date.now(), id, name, host, verdict: r.verdict, limited: r.limited, reasons: r.reasons, sha: sha ? sha.slice(0, 16) : null };
    const { dlresults = [] } = await chrome.storage.session.get("dlresults");
    await chrome.storage.session.set({ dlresults: [...dlresults.slice(-9), rec] });

    if (r.verdict === "problem") cloud.alertGuardians("download", parseHost(host).domain || host || "unknown.invalid", false);
    // Quiet for harmless things (pictures, text); speak up for anything risky-looking or any problem.
    if (r.verdict === "nothing" && !r.risky) return;
    const msg = { type: "dl:result", id, name, host, verdict: r.verdict, limited: r.limited, reasons: r.reasons.filter((x) => x.sev !== "info").slice(0, 4).map((x) => x.text), referrer: item.referrer || "" };
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map((t) => chrome.tabs.sendMessage(t.id, msg, { frameId: 0 }).catch(() => null)));
  } catch {}
}

chrome.runtime.onMessage.addListener((msg, sender, send) => {
  if (msg?.type === "dl:last") { chrome.storage.session.get("dlresults").then((r) => send(r.dlresults || [])); return true; }
  if (msg?.type === "dl:delete" && chrome.downloads) {
    (async () => { try { await chrome.downloads.removeFile(msg.id); } catch {} try { await chrome.downloads.erase({ id: msg.id }); } catch {} send({ ok: true }); })();
    return true;
  }
});

// Dev only (npm run dev): reload the extension by itself when the build changes. Not in the release build.
if (__DEV__) {
  let stamp = null;
  setInterval(async () => {
    try { const b = await (await fetch(chrome.runtime.getURL("build.json"), { cache: "no-store" })).json(); if (stamp && b.stamp !== stamp) chrome.runtime.reload(); stamp = b.stamp; } catch {}
  }, 1500);
}
