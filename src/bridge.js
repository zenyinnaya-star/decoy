// Isolated-world relay, runs in EVERY frame at document_start.
// Talks to the page watcher through DOM events, and to the background through runtime messages.
const isTop = window === window.top;

// The service worker can be asleep; one retry wakes it. Losing a guard event is better than throwing in the page.
const post = (m, tries = 2) => {
  try { chrome.runtime.sendMessage(m).catch(() => { if (tries > 1) setTimeout(() => post(m, tries - 1), 400); }); } catch {}
};

// Tell the in-page guards about your settings (pause on this site, per-guard switches, trusted site).
const sendCfg = (c) => document.dispatchEvent(new CustomEvent("decoy:config", { detail: JSON.stringify(c) }));
const loadCfg = () => { try { chrome.runtime.sendMessage({ type: "guard:config" }).then((c) => c && sendCfg(c)).catch(() => {}); } catch {} };
loadCfg();
try { chrome.storage.onChanged.addListener((ch, area) => { if (area === "local" && (ch.paused || ch.off)) loadCfg(); }); } catch {}

const arm = (needles, submitted) =>
  document.dispatchEvent(new CustomEvent("decoy:arm", { detail: JSON.stringify({ needles, submitted: !!submitted }) }));
const disarm = () => document.dispatchEvent(new CustomEvent("decoy:disarm"));

// Shared with content.js (same isolated world, invisible to the page).
globalThis.__decoyBridge = { arm, disarm, isTop };

// Watcher -> background. Page scripts can dispatch this event too, so the background validates it.
document.addEventListener("decoy:hit", (e) => {
  try { post({ type: "dummy:hit", hit: JSON.parse(e.detail) }); } catch {}
});

// Guard events (clipboard / permissions / scareware). The background validates them too.
document.addEventListener("decoy:guard", (e) => {
  try { post({ type: "guard:event", kind: JSON.parse(e.detail).kind }); } catch {}
});
document.addEventListener("decoy:guardclose", () => { try { chrome.runtime.sendMessage({ type: "guard:close" }).catch(() => {}); } catch {} });

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "dummy:needles") arm(msg.needles, msg.submitted);
  if (msg?.type === "dummy:disarm") disarm();
});

// Page just loaded (maybe after the form submitted): is this tab being tested?
try {
  chrome.runtime.sendMessage({ type: "dummy:hello" }).then((r) => {
    if (r?.armed) arm(r.needles, r.submitted);
  }).catch(() => {});
} catch {}
