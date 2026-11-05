import { computeScore } from "./score.js";
import { buildChecklist, GIVEN } from "./recovery.js";
import { analyze, sha256hex } from "./filecheck.js";
import { explain } from "./flags.js";
import * as cloud from "./cloud.js";

const $ = (id) => document.getElementById(id);
const forcedTab = new URLSearchParams(location.search).get("tab"); // dev/test only: point the popup at a specific tab
const tab = () => (forcedTab ? chrome.tabs.get(+forcedTab) : chrome.tabs.query({ active: true, currentWindow: true }).then((t) => t[0]));
const send = (id, type) => chrome.tabs.sendMessage(id, { type }, { frameId: 0 });
// Pages opened before Decoy was installed or updated have no scripts yet: add them now (activeTab allows it), then retry.
async function inject(t) {
  const target = { tabId: t.id, allFrames: false };
  await chrome.scripting.executeScript({ target, files: ["bridge.js"] });
  await chrome.scripting.executeScript({ target, files: ["watcher.js", "guard.js"], world: "MAIN" });
  await chrome.scripting.executeScript({ target, files: ["content.js"] });
}
const toTab = async (type) => {
  const t = await tab();
  try { return await send(t.id, type); }
  catch (e) {
    if (!/^(https?|file):/.test(t.url || "")) throw e;
    await inject(t);
    return send(t.id, type);
  }
};

// Why a page can't be scanned, in plain words. Chrome itself blocks extensions on some pages.
async function whyNot(t) {
  const u = t?.url || "";
  if (!u || /^(chrome|edge|about|chrome-search|chrome-untrusted|devtools):/.test(u)) return ["Chrome's own page", "Chrome doesn't let any extension run on its own pages (settings, new tab, downloads). Nothing here to scan."];
  if (/^chrome-extension:/.test(u)) return ["An extension page", "Chrome keeps extension pages private from other extensions."];
  if (/^view-source:/.test(u)) return ["Source view", "Open the normal page to scan it."];
  if (/^https:\/\/(chrome\.google\.com\/webstore|chromewebstore\.google\.com)/.test(u)) return ["Chrome Web Store", "Chrome blocks extensions on the Web Store. This is Google's own site."];
  if (/^file:/.test(u)) {
    let ok = false; try { ok = await chrome.extension.isAllowedFileSchemeAccess(); } catch {}
    if (!ok) return ["Local file", "To scan files on your computer, switch on \"Allow access to file URLs\" for Decoy in chrome://extensions."];
  }
  if (/\.pdf($|[?#])/i.test(u)) return ["PDF in Chrome's viewer", "Chrome's PDF viewer blocks extensions. Download the file and use \"Check a file\" under More protection."];
  return ["Can't scan this page", "This page didn't answer. Try Rescan, or reload the page once."];
}

let current = null;
let pageScore = 0;

const TRUST_NOTE = {
  popular: "Top-ranked site, page checks skipped",
  institution: "Government / education site, page checks skipped",
  you: "You trust this site, page checks skipped",
};

const levelKey = (n) => (n < 20 ? "ok" : n < 45 ? "a-bit-off" : n < 70 ? "sketchy" : "likely");
const ARC = 2 * Math.PI * 50;
const CAP_NOTE = {
  "weak-only": "Weak signs on their own never go above \"A bit off\".",
  "one-strong": "One strong sign tops out at \"Sketchy\". \"Likely scam\" needs two strong signs or a match on a known scam list.",
};

// Site logo in the tile: the tab's own favicon (already loaded by the browser). Letter is the fallback.
let favUrl = "";
tab().then((t) => { favUrl = t && /^(https?:|data:image\/)/.test(t.favIconUrl || "") ? t.favIconUrl : ""; setTile(); }).catch(() => {});
let tileLetter = "·";
function setTile(letter) {
  if (letter) tileLetter = letter;
  const el = $("tile");
  if (!favUrl) { el.textContent = tileLetter; el.classList.remove("logo"); return; }
  if (el.querySelector("img")?.src === favUrl) return;
  const img = new Image();
  img.alt = "";
  img.onerror = () => { favUrl = ""; setTile(); };
  img.onload = () => { el.replaceChildren(img); el.classList.add("logo"); };
  img.src = favUrl;
}

function render(res) {
  const r = computeScore(res.flags, { trustKind: res.trustKind });
  pageScore = r.score;
  document.body.dataset.level = levelKey(r.score);
  $("score").textContent = r.score;
  $("arc").setAttribute("stroke-dasharray", `${(r.score / 100) * ARC} ${ARC}`);
  $("arc").classList.toggle("zero", r.score === 0);
  $("level").textContent = r.level;
  $("sub").textContent = r.sub;
  setTile((res.domain || $("host").textContent || "·").replace(/^www\./, "")[0] || "·");
  $("hostline").textContent = res.domain && res.age != null ? `Registered ${res.age} day(s) ago` : "Scanned just now. Nothing left your browser.";

  const note = $("trustnote");
  note.hidden = !res.trustKind;
  if (res.trustKind) note.textContent = TRUST_NOTE[res.trustKind];

  const ul = $("flags");
  ul.replaceChildren();
  const ex = explain(r.flags);
  const strong = ex.filter((f) => f.tier === "strong").length, weak = ex.length - strong;
  $("flagshead").textContent = ex.length ? "Why this score" : "What we checked";
  $("flagcount").textContent = ex.length ? `${strong} strong, ${weak} weak` : "";
  if (!ex.length && !res.trustKind) {
    for (const t of ["Address looks normal", "No forms send data to other sites", "No scare or pressure language", "Nothing risky seen from page scripts"]) {
      const li = document.createElement("li"); li.className = "chk"; li.textContent = t; ul.append(li);
    }
  }
  $("flagshead").parentElement.hidden = !ex.length && !!res.trustKind;
  for (const f of ex) {
    const li = document.createElement("li");
    li.className = f.tier;
    const h = document.createElement("div"); h.className = "h";
    const tag = document.createElement("span"); tag.className = "tag " + (f.tier === "strong" ? "s" : "w"); tag.textContent = f.tier === "strong" ? "Strong" : "Weak";
    const t = document.createElement("span"); t.className = "t"; t.textContent = f.label; // textContent only: labels contain page data
    const p = document.createElement("span"); p.className = "p"; p.textContent = `+${f.weight}`;
    h.append(tag, t, p); li.append(h);
    if (f.why) { const w = document.createElement("div"); w.className = "why"; w.textContent = f.why; li.append(w); }
    ul.append(li);
  }
  $("capnote").hidden = !r.capped || !ex.length;
  $("capnote").textContent = CAP_NOTE[r.capped] || "";

  const risky = r.score >= 45;
  $("leave").hidden = !risky;
  $("warnrow").hidden = !risky;
  $("reportlink").hidden = risky;

  const btn = $("trust");
  btn.hidden = !res.domain || (res.trusted && !res.userTrusted);
  btn.textContent = res.userTrusted ? "Stop trusting this site" : "I trust this site";
  resetTestButton();
}

async function run() {
  $("level").textContent = "Scanning…";
  try {
    const s = await toTab("scan");
    $("host").textContent = s.host;
    current = await chrome.runtime.sendMessage({ type: "assess", scan: s });
    try {
      const guards = await chrome.runtime.sendMessage({ type: "guard:state", tabId: (await tab()).id });
      // Behaviour seen on the page is strong evidence, so it joins the flag list.
      current.flags = [...current.flags, ...guards.map((g) => ({ id: g.id, label: g.label + (g.n > 1 ? ` (x${g.n})` : ""), weight: g.weight, tier: g.tier }))];
    } catch {}
    render(current);
  } catch {
    document.body.dataset.level = "scan";
    $("arc").setAttribute("stroke-dasharray", `0 ${ARC}`);
    const t0 = await tab().catch(() => null);
    try { $("host").textContent = new URL(t0.url).hostname || t0.url.split(":")[0] + " page"; } catch { $("host").textContent = "This page"; }
    const [title, why] = await whyNot(t0);
    $("level").textContent = title;
    $("sub").textContent = why;
    $("score").textContent = "–";
    $("flagshead").parentElement.hidden = true;
  }
}

// ---- dummy test ------------------------------------------------------------------------------
let confirming = false, confirmTimer = null;

function resetTestButton() {
  confirming = false;
  clearTimeout(confirmTimer);
  $("dtest").textContent = current?.trusted && !current.userTrusted
    ? "Test anyway (well-known site, usually not needed)…"
    : "Test with dummy…";
}

$("dtest").onclick = async () => {
  if (!confirming) {
    confirming = true;
    $("dtest").textContent = "Tap again to start. Real sites may create a junk account.";
    confirmTimer = setTimeout(resetTestButton, 6000);
    return;
  }
  resetTestButton();
  try {
    const r = await toTab("dummy:start");
    $("msg").textContent = r.filled ? `Dummy filled ${r.filled} field(s). Now submit the form yourself.` : "No fillable fields found";
  } catch {
    $("msg").textContent = "Can't run the dummy test on this page";
  }
  refreshDummy();
};

$("dstop").onclick = async () => {
  await chrome.runtime.sendMessage({ type: "dummy:stop", tabId: (await tab()).id });
  refreshDummy();
};

const MARK = { strong: "Strong", warn: "Warn", info: "Info" };

function renderDummy(d) {
  const box = $("dummy");
  if (!d?.armed) { box.hidden = true; $("dtest").hidden = false; return; }
  const v = d.verdict;
  box.hidden = false;
  $("dtest").hidden = true;
  box.dataset.status = v.status;
  $("dtitle").textContent = v.title;
  $("dhost").textContent = d.host ? `Test started on ${d.host}` : "";
  $("dsub").textContent = v.sub;
  $("dlimit").textContent = v.limit;
  const ul = $("ditems");
  ul.replaceChildren();
  for (const it of v.items) {
    const li = document.createElement("li");
    li.className = it.severity;
    const m = document.createElement("i");
    m.textContent = MARK[it.severity] || "";
    const t = document.createElement("span");
    t.textContent = it.text; // contains hostnames from the page: textContent only
    li.append(m, t);
    ul.append(li);
  }
}

async function refreshDummy() {
  try {
    const t = await tab();
    renderDummy(await chrome.runtime.sendMessage({ type: "dummy:state", tabId: t.id, pageScore }));
  } catch {}
}

$("fill").onclick = async () => {
  try {
    const r = await toTab("fill");
    $("msg").textContent = r.filled ? `Filled ${r.filled} field(s) as ${r.persona.name}` : "No fillable fields found";
  } catch {
    $("msg").textContent = "Can't fill on this page";
  }
};
$("rescan").onclick = run;
$("trust").onclick = async () => {
  await chrome.runtime.sendMessage({ type: "trust", domain: current.domain, on: !current.userTrusted });
  run();
};

run().then(refreshDummy);
setInterval(refreshDummy, 1500); // live while the popup is open


// ---- More protection ---------------------------------------------------------------------------
(async () => {
  const { mode = "auto" } = await chrome.storage.local.get("mode");
  const showMode = (m) => {
    for (const b of document.querySelectorAll("#seg button")) b.setAttribute("aria-pressed", String(b.dataset.m === m));
    $("autotext").textContent = m === "auto" ? "Auto-scan on" : m === "ask" ? "Ask before scanning" : "Auto-scan off";
    $("autopill").classList.toggle("off", m === "off");
  };
  showMode(mode);
  for (const b of document.querySelectorAll("#seg button")) b.onclick = () => { chrome.storage.local.set({ mode: b.dataset.m }); showMode(b.dataset.m); };
  const showAds = (on) => {
    $("ads").checked = on;
    $("adbtn").setAttribute("aria-pressed", String(on));
    $("adbtn").classList.toggle("on", on);
    $("adbtntext").textContent = on ? "Block ads: On" : "Block ads: Off";
  };
  showAds((await chrome.runtime.sendMessage({ type: "ads:get" }))?.on || false);
  const setAds = async (on) => { const r = await chrome.runtime.sendMessage({ type: "ads:set", on }); showAds(!!r?.on); if (r?.on !== undefined) { $("msg").textContent = r.on ? "Ad blocking on. Reload this page to apply it." : "Ad blocking off."; } };
  $("ads").onchange = () => setAds($("ads").checked);
  $("adbtn").onclick = () => setAds(!$("adbtn").classList.contains("on"));
  $("trk").checked = (await chrome.runtime.sendMessage({ type: "trackers:get" }))?.on || false;
  $("trk").onchange = () => chrome.runtime.sendMessage({ type: "trackers:set", on: $("trk").checked });
})();

$("precheck").onclick = async () => {
  const out = $("preout"); out.replaceChildren();
  const r = await chrome.runtime.sendMessage({ type: "precheck", text: $("pre").value });
  const lv = document.createElement("div"); lv.className = "lv"; lv.textContent = `${r.level}${r.score ? ` (${r.score})` : ""}`; lv.style.color = r.color;
  out.append(lv);
  if (r.items.length) for (const it of r.items) { const d = document.createElement("div"); d.textContent = `${it.host}: ${it.level}`; out.append(d); }
  if (r.reasons.length) { const ul = document.createElement("ul"); for (const x of r.reasons) { const li = document.createElement("li"); li.textContent = x; ul.append(li); } out.append(ul); }
  else { const d = document.createElement("div"); d.textContent = r.hadUrls ? r.sub : "No link or warning wording found. Still be careful with anything unexpected."; out.append(d); }
};

$("rec").onclick = () => {
  $("recbox").hidden = false; $("rec").hidden = true;
  const pick = $("recpick");
  for (const [k, label] of GIVEN) {
    const l = document.createElement("label"); const c = document.createElement("input"); c.type = "checkbox"; c.value = k;
    c.onchange = () => {
      const ks = [...pick.querySelectorAll("input:checked")].map((x) => x.value);
      $("recout").replaceChildren(...(ks.length ? buildChecklist(ks) : []).map((s) => { const li = document.createElement("li"); li.textContent = s; return li; }));
    };
    l.append(c, " " + label); pick.append(l);
  }
};
$("recremind").onclick = async () => {
  if (!(await chrome.permissions.contains({ permissions: ["notifications"] })) && !(await chrome.permissions.request({ permissions: ["notifications"] }))) { $("recremind").textContent = "Needs notification permission"; return; }
  await chrome.runtime.sendMessage({ type: "recovery:remind" }); $("recremind").textContent = "Reminder set for tomorrow"; };


// ---- Problem fixes: pause, per-guard switches, optional permissions, privacy opt-in, reporting ------------
const domainOf = async () => (current && current.domain) || (await tab()).url && new URL((await tab()).url).hostname;

(async () => {
  const { paused = [], off = {}, ageLookup = false } = await chrome.storage.local.get(["paused", "off", "ageLookup"]);
  const dom = current?.domain;
  $("pause").textContent = dom && paused.includes(dom) ? "Resume Decoy on this site" : "Pause Decoy on this site";
  for (const c of document.querySelectorAll("[data-g]")) {
    c.checked = !off[c.dataset.g];
    c.onchange = async () => {
      const o = (await chrome.storage.local.get("off")).off || {};
      o[c.dataset.g] = !c.checked; await chrome.storage.local.set({ off: o });
    };
  }
  $("age").checked = !!ageLookup;
  $("age").onchange = () => chrome.storage.local.set({ ageLookup: $("age").checked });
  $("dl").checked = await chrome.permissions.contains({ permissions: ["downloads"] });
  $("dl").onchange = async () => {
    if ($("dl").checked) $("dl").checked = await chrome.permissions.request({ permissions: ["downloads"] });
    else await chrome.permissions.remove({ permissions: ["downloads"] });
  };
  try {
    const b = await (await fetch(chrome.runtime.getURL("build.json"))).json();
    const days = Math.floor((Date.now() - new Date(b.date).getTime()) / 86400000);
    $("listage").textContent = days > 120 ? `Safe-site list is ${days} days old. Rebuild with: npm run lists && npm run build` : `Safe-site list built ${b.date}.`;
  } catch {}
})();

$("pause").onclick = async () => {
  const dom = (await domainOf()) || "";
  if (!dom) return;
  const { paused = [] } = await chrome.storage.local.get("paused");
  const next = paused.includes(dom) ? paused.filter((d) => d !== dom) : [...paused, dom];
  await chrome.storage.local.set({ paused: next });
  $("pause").textContent = next.includes(dom) ? "Resume Decoy on this site (reload the tab)" : "Pause Decoy on this site (reload the tab)";
};

// "Report wrong score": domain + flag ids only. No path, no page text, nothing typed.
const reportWrong = async () => {
  if (!current) return;
  const r = computeScore(current.flags, { trustKind: current.trustKind });
  const text = ["Decoy score report", `domain: ${current.domain || "?"}`, `score: ${r.score} (${r.level})`,
    `flags: ${r.flags.map((f) => `${f.id}${f.tier === "strong" ? "!" : ""}`).join(", ") || "-"}`, `trust: ${current.trustKind || "none"}`,
    `version: ${chrome.runtime.getManifest().version}`].join("\n");
  const { reports = [] } = await chrome.storage.local.get("reports");
  await chrome.storage.local.set({ reports: [...reports.slice(-49), { t: Date.now(), text }] });
  try { await navigator.clipboard.writeText(text); $("msg").textContent = "Copied. Paste it wherever you track bugs. It has no page content."; }
  catch { $("msg").textContent = "Saved locally (clipboard blocked)."; }
};
$("report").onclick = reportWrong; $("reportlink").onclick = reportWrong;

// ---- header gear, leave button, quick recovery ------------------------------------------------
$("gear").onclick = () => { const d = $("more"); d.open = !d.open; if (d.open) d.scrollIntoView({ block: "start" }); };
$("leave").onclick = async () => {
  const t = await tab();
  try { await chrome.tabs.update(t.id, { url: "chrome://newtab/" }); } catch { try { await chrome.tabs.remove(t.id); } catch {} }
  window.close();
};
$("entered").onclick = () => { $("more").open = true; if (!$("rec").hidden) $("rec").click(); $("recbox").scrollIntoView({ block: "center" }); };


// ---- Check a file: runs here, in the popup. The file is never uploaded. -----------------------------------
const VERDICT = { problem: ["Problem found", "#ff5d5d"], careful: ["Be careful", "#ff9f43"], nothing: ["Nothing suspicious found", "#7ee2a0"] };
$("filepick").onchange = async () => {
  const f = $("filepick").files[0]; const out = $("fileout"); out.replaceChildren();
  if (!f) return;
  const head = new Uint8Array(await f.slice(0, 2 * 1024 * 1024).arrayBuffer());
  const tail = f.size > head.length ? new Uint8Array(await f.slice(Math.max(head.length, f.size - 256 * 1024)).arrayBuffer()) : null;
  const r = analyze({ name: f.name, head, tail, size: f.size, source: null });
  const [label, color] = VERDICT[r.verdict];
  const v = document.createElement("div"); v.className = "lv"; v.textContent = label; v.style.color = color; out.append(v);
  const ul = document.createElement("ul");
  for (const x of r.reasons) { const li = document.createElement("li"); li.textContent = x.text; ul.append(li); }
  if (r.reasons.length) out.append(ul);
  if (r.verdict === "nothing") { const d = document.createElement("div"); d.textContent = "That is not a guarantee the file is safe. Decoy checks for tricks, not for every virus."; out.append(d); }
  if (f.size <= 64 * 1024 * 1024) { const s = document.createElement("div"); s.className = "foot"; s.textContent = "SHA-256: " + (await sha256hex(await f.arrayBuffer())); out.append(s); }
};
(async () => {
  let ok = false; try { ok = await chrome.extension.isAllowedFileSchemeAccess(); } catch {}
  $("fileaccess").textContent = ok ? "Download check can look inside finished downloads." : "Download check is limited to names and sources. To let it look inside files, switch on \"Allow access to file URLs\" for Decoy.";
  $("fileaccessbtn").hidden = ok;
  $("fileaccessbtn").onclick = () => chrome.tabs.create({ url: `chrome://extensions/?id=${chrome.runtime.id}` });
})();


// ---- Protect each other: shared warnings + trusted people (all opt-in) -------------------------------------
const okUrl = (u) => { try { const x = new URL(u); return x.protocol === "https:" || (x.protocol === "http:" && /^(localhost|127\.0\.0\.1)$/.test(x.hostname)); } catch { return false; } };

async function showGuardians() {
  const ul = $("glist"); ul.replaceChildren();
  let list = [];
  try { list = await cloud.guardians(); } catch (e) { $("gmsg").textContent = e.message; return; }
  for (const g of list) {
    const li = document.createElement("li");
    const n = document.createElement("span"); n.textContent = g.name; // names come from the server: textContent only
    const st = document.createElement("small"); st.textContent = g.status === "active" ? "active" : "waiting for their yes";
    const rm = document.createElement("button"); rm.className = "btn"; rm.textContent = "Remove";
    rm.onclick = async () => { rm.disabled = true; try { await cloud.removeGuardian(g.id); } catch (e) { $("gmsg").textContent = e.message; } showGuardians(); };
    li.append(n, st, rm); ul.append(li);
  }
}

async function connect(save) {
  const url = $("cloudurl").value.trim().replace(/\/+$/, "");
  if (save) {
    if (!okUrl(url)) { $("cloudstatus").textContent = "Use an https:// address (http is only allowed for localhost)."; return; }
    await chrome.storage.local.set({ cloudUrl: url });
  }
  if (!url) { $("cloudbox").hidden = true; return; }
  try { await cloud.ping(); $("cloudstatus").textContent = "Connected."; $("cloudbox").hidden = false; showGuardians(); }
  catch { $("cloudstatus").textContent = "Couldn't reach it. Check the address and that the worker is deployed."; $("cloudbox").hidden = true; }
}

(async () => {
  const s = await chrome.storage.local.get(["cloudUrl", "useShared", "shareReports"]);
  $("cloudurl").value = s.cloudUrl || "";
  $("useshared").checked = !!s.useShared; $("sharereports").checked = !!s.shareReports;
  $("cloudsave").onclick = () => connect(true);
  $("useshared").onchange = async () => { await chrome.storage.local.set({ useShared: $("useshared").checked }); if ($("useshared").checked) chrome.runtime.sendMessage({ type: "cloud:sync" }); };
  $("sharereports").onchange = () => chrome.storage.local.set({ shareReports: $("sharereports").checked });
  $("ginvite").onclick = async () => {
    const name = $("gname").value.trim(), email = $("gemail").value.trim(), you = $("gyou").value.trim();
    if (!name || !email || !you) { $("gmsg").textContent = "Add their name, their email and your name."; return; }
    $("ginvite").disabled = true;
    try { await cloud.invite(email, name, you); $("gmsg").textContent = `Invite sent to ${name}. Nothing is shared until they say yes.`; $("gname").value = $("gemail").value = ""; }
    catch (e) { $("gmsg").textContent = e.message; }
    $("ginvite").disabled = false; showGuardians();
  };
  if (s.cloudUrl) connect(false);
})();

// Which build is this? Helps tell whether a reload picked up the latest code.
(async () => { try { const b = await (await fetch(chrome.runtime.getURL("build.json"))).json(); $("ver").textContent = `v${chrome.runtime.getManifest().version} · built ${b.date}${b.stamp ? " " + new Date(b.stamp).toISOString().slice(11, 16) + " UTC" : ""}`; } catch {} })();
