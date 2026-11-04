// Top frame only (document_idle). Scan, fill, and the dummy-test controls.
import { scan } from "./scanner.js";
import { fill } from "./fill.js";
import { makeCanary, buildNeedles } from "./canary.js";
import { start as startProtect, setTesting, notice, askDownload, showDownloadResult } from "./protect.js";

const send = (m) => chrome.runtime.sendMessage(m).catch(() => null);

// ---- small "Decoy is watching" banner -------------------------------------------------------
function showOverlay() {
  if (document.getElementById("decoy-overlay-host")) return;
  const host = document.createElement("div");
  host.id = "decoy-overlay-host";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `.b{all:initial;position:fixed;z-index:2147483647;right:12px;bottom:12px;display:flex;gap:10px;align-items:center;
    background:#12141a;color:#e8eaf0;font:13px/1.3 system-ui,sans-serif;padding:9px 12px;border-radius:10px;border:1px solid #6c8cff;box-shadow:0 4px 16px #0006}
    button{all:initial;cursor:pointer;color:#fff;background:#6c8cff;border-radius:6px;padding:4px 9px;font:600 12px system-ui}`;
  const box = document.createElement("div");
  box.className = "b";
  const label = document.createElement("span");
  label.textContent = "Decoy is watching. Submit the form yourself.";
  const stop = document.createElement("button");
  stop.textContent = "Stop";
  stop.onclick = () => { send({ type: "dummy:stop" }); host.remove(); };
  box.append(label, stop);
  root.append(style, box);
  document.documentElement.append(host);
}
const hideOverlay = () => document.getElementById("decoy-overlay-host")?.remove();

// ---- what does this page ask for next? (used after a "login" was submitted) -----------------
const ASKS = [
  [/otp|one.?time|verification.?code|2fa|auth.?code|sms.?code/, "a one-time code"],
  [/ssn|social.?sec|\bsin\b/, "a social security / insurance number"],
  [/passport|driver|licen[cs]e|id.?(upload|card|number)/, "an ID document"],
  [/card.?number|cc-number|cvv|cvc/, "card details"],
];
function extraAsk() {
  const out = new Set();
  document.querySelectorAll("input, textarea, select").forEach((el) => {
    const s = [el.type, el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute("aria-label"), el.labels?.[0]?.textContent]
      .join(" ").toLowerCase();
    for (const [re, label] of ASKS) if (re.test(s)) out.add(label);
  });
  return [...out];
}

const reportPage = () => send({
  type: "dummy:page", href: location.href, host: location.hostname, referrer: document.referrer, extraAsk: extraAsk(),
});

// If this tab is being tested, show the banner and tell the background where we are now.
send({ type: "dummy:hello" }).then((r) => { if (r?.armed) { setTesting(true); showOverlay(); reportPage(); } });
startProtect().catch(() => {}); // background scan + notice (mode: auto / ask / off)

// ---- popup commands ------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, _s, reply) => {
  if (msg?.type === "decoy:notice") { notice(msg.notice); return; }
  if (msg?.type === "dl:result") { reply({ shown: showDownloadResult(msg) }); return; }
  if (msg?.type === "dl:ask") { reply({ shown: askDownload(msg) }); return; }
  if (msg?.type === "scan") { reply(scan(document, location)); return; }
  if (msg?.type === "fill") { reply(fill()); return; }

  if (msg?.type === "dummy:start") {
    (async () => {
      setTesting(true); // you chose to test this site: get the warning screens out of the way
      const id = makeCanary();
      const needles = await buildNeedles(id);
      // Arm FIRST so the watcher sees everything the page does while we fill (including keystroke-style listeners).
      globalThis.__decoyBridge?.arm(needles, false);
      await send({ type: "dummy:arm", needles, host: location.hostname, hadPassword: !!document.querySelector('input[type="password"]') });
      const r = fill(document, location.hostname, id);
      showOverlay();
      reply({ ok: true, filled: r.filled });
    })();
    return true; // async reply
  }
  if (msg?.type === "dummy:disarm") { hideOverlay(); setTesting(false); }
});
