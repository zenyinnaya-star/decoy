// Shared plumbing every guard gets. Runs in the page (MAIN world). Guards never touch each other, only ctx.
import { LURE } from "../guard-rules.js";

export function makeCtx() {
  // Settings from the extension (pause on this site, per-guard switches, trusted site). Starts ON; the bridge updates it within milliseconds.
  let cfg = { paused: false, off: {}, trusted: false };
  let ready = false; const waiting = [];
  const flush = () => { ready = true; while (waiting.length) { try { waiting.shift()(); } catch {} } };
  const whenReady = (fn) => { if (ready) fn(); else { waiting.push(fn); setTimeout(flush, 2500); } };
  document.addEventListener("decoy:config", (e) => { try { cfg = { ...cfg, ...JSON.parse(e.detail) }; } catch {} flush(); });

  const on = (name, trustedSkips = false) => !cfg.paused && !(cfg.off && cfg.off[name]) && !(trustedSkips && cfg.trusted);
  // Opt-in features (default OFF): on only when the popup has explicitly set off[name] === false.
  const opt = (name) => !cfg.paused && !!cfg.off && cfg.off[name] === false;
  const gesture = () => { try { return navigator.userActivation ? navigator.userActivation.isActive : true; } catch { return true; } };
  const lure = () => { try { return LURE.test((document.body?.innerText || "").slice(0, 20000)); } catch { return false; } };

  // The finding bus (page side): one event, the bridge forwards it to the background.
  const emit = (kind) => { try { document.dispatchEvent(new CustomEvent("decoy:guard", { detail: JSON.stringify({ kind, host: location.hostname }) })); } catch {} };
  const closeTab = () => document.dispatchEvent(new CustomEvent("decoy:guardclose"));

  // ---- tiny in-page chip (closed shadow root; only real clicks count) ----
  let box, root;
  const ensure = () => {
    if (box && box.isConnected) return root;
    box = document.createElement("div");
    box.style.cssText = "all:initial;position:fixed;z-index:2147483647;right:12px;bottom:12px;display:flex;flex-direction:column;gap:8px;max-width:320px";
    root = box.attachShadow({ mode: "closed" });
    const st = document.createElement("style");
    st.textContent = `.c{font:13px/1.35 system-ui,sans-serif;background:#fff;color:#1d1d1f;border:1px solid #d33;border-left:5px solid #d33;border-radius:8px;padding:10px 12px;box-shadow:0 4px 16px #0003}
      .t{font-weight:600;margin-bottom:4px}.r{display:flex;gap:6px;margin-top:8px}button{font:inherit;padding:4px 10px;border:1px solid #888;border-radius:6px;background:#f3f3f3;cursor:pointer;color:#111}
      button.p{background:#d33;color:#fff;border-color:#d33}`;
    root.append(st);
    (document.documentElement || document).append(box);
    return root;
  };
  // buttons: [label, fn, primary]. The "Allow this once" button of a guard is just a non-primary button that runs the real action.
  const chip = (title, text, buttons) => {
    const r = ensure();
    const c = document.createElement("div"); c.className = "c";
    const t = document.createElement("div"); t.className = "t"; t.textContent = title;
    const p = document.createElement("div"); p.textContent = text;
    const row = document.createElement("div"); row.className = "r";
    const done = () => c.remove();
    for (const [label, fn, primary] of buttons) {
      const b = document.createElement("button"); b.textContent = label; if (primary) b.className = "p";
      b.addEventListener("click", (e) => { if (!e.isTrusted) return; done(); try { fn(); } catch {} });
      row.append(b);
    }
    c.append(t, p, row); r.append(c);
    return done;
  };
  // Standard "Allow this once" chip used by blockers.
  const allowOnce = (title, text, allow, keepLabel = "Keep blocked") => chip(title, text, [[keepLabel, () => {}, true], ["Allow this once", allow]]);

  // Patching with an undo list, so a guard can be switched off cleanly.
  const undo = [];
  const patch = (obj, key, make) => {
    if (!obj) return false;
    const orig = obj[key]; if (typeof orig !== "function") return false;
    obj[key] = make(orig);
    undo.push(() => { try { obj[key] = orig; } catch {} });
    return true;
  };
  const patchDesc = (obj, key, make) => {
    const d = Object.getOwnPropertyDescriptor(obj, key); if (!d) return false;
    Object.defineProperty(obj, key, make(d));
    undo.push(() => { try { Object.defineProperty(obj, key, d); } catch {} });
    return true;
  };
  const teardown = () => { while (undo.length) undo.pop()(); };

  return { get cfg() { return cfg; }, on, opt, gesture, lure, emit, closeTab, chip, allowOnce, whenReady, patch, patchDesc, teardown };
}
