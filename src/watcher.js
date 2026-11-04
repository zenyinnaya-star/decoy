// Runs INSIDE the page (world: MAIN) at document_start, in every frame.
// Dormant until the extension arms it with a list of dummy values ("needles").
// Every hook is a pass-through: it looks, reports, then calls the original untouched.
import { matchNeedles } from "./match.js";
import { snapshot, disguiseAll } from "./stealth.js";

(() => {
  const __snap = snapshot([
    () => [window, "fetch"], () => [XMLHttpRequest.prototype, "open"], () => [XMLHttpRequest.prototype, "send"],
    () => [Navigator.prototype, "sendBeacon"], () => [WebSocket.prototype, "send"], () => [HTMLFormElement.prototype, "submit"],
    () => [HTMLImageElement.prototype, "src"], () => [HTMLScriptElement.prototype, "src"], () => [HTMLIFrameElement.prototype, "src"],
  ]);
  let needles = [];
  let armed = false;
  let submitted = false;

  const send = (o) => { try { document.dispatchEvent(new CustomEvent("decoy:hit", { detail: JSON.stringify(o) })); } catch {} };

  document.addEventListener("decoy:arm", (e) => {
    try {
      const d = JSON.parse(e.detail);
      needles = Array.isArray(d.needles) ? d.needles : [];
      submitted = !!d.submitted;
      armed = needles.length > 0;
    } catch {}
  });
  document.addEventListener("decoy:disarm", () => { armed = false; needles = []; submitted = false; });

  const text = (v) => {
    if (v == null) return "";
    if (typeof v === "string") return v;
    if (v instanceof URLSearchParams) return v.toString();
    if (typeof FormData !== "undefined" && v instanceof FormData) return [...v.entries()].map(([k, x]) => `${k}=${typeof x === "string" ? x : ""}`).join("&");
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return new TextDecoder().decode(v instanceof ArrayBuffer ? v : v.buffer);
    return "";
  };

  const check = (url, body, via) => {
    if (!armed) return;
    try {
      const u = String(url);
      const run = (b) => {
        const hits = matchNeedles(`${u}\n${b}`, needles);
        if (hits.length) send({ url: new URL(u, location.href).href, via, hits, beforeSubmit: !submitted, t: Date.now() });
      };
      if (typeof Blob !== "undefined" && body instanceof Blob) body.text().then(run).catch(() => run(""));
      else run(text(body));
    } catch {}
  };

  // fetch
  const _fetch = window.fetch;
  if (_fetch) {
    window.fetch = function (input, init) {
      try {
        if (armed) {
          const isReq = typeof Request !== "undefined" && input instanceof Request;
          const url = isReq ? input.url : input;
          const body = init && init.body != null ? init.body : null;
          check(url, body, "fetch");
          if (isReq && body == null && input.method !== "GET" && input.method !== "HEAD") input.clone().text().then((t) => check(url, t, "fetch")).catch(() => {});
        }
      } catch {}
      return _fetch.apply(this, arguments);
    };
  }

  // XMLHttpRequest
  const _open = XMLHttpRequest.prototype.open;
  const _xsend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) { try { this.__decoyUrl = url; } catch {} return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function (body) { try { check(this.__decoyUrl, body, "xhr"); } catch {} return _xsend.apply(this, arguments); };

  // navigator.sendBeacon
  if (navigator.sendBeacon) {
    const _beacon = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = function (url, data) { try { check(url, data, "beacon"); } catch {} return _beacon.apply(this, arguments); };
  }

  // WebSocket
  const _wsSend = WebSocket.prototype.send;
  WebSocket.prototype.send = function (data) { try { check(this.url, data, "websocket"); } catch {} return _wsSend.apply(this, arguments); };

  // Tracking pixels / JSONP: img.src, script.src, iframe.src
  for (const C of [HTMLImageElement, HTMLScriptElement, HTMLIFrameElement]) {
    const d = Object.getOwnPropertyDescriptor(C.prototype, "src");
    if (!d || !d.set) continue;
    Object.defineProperty(C.prototype, "src", {
      ...d,
      set(v) { try { check(v, null, "pixel"); } catch {} d.set.call(this, v); },
    });
  }

  // Form submission (the data may leave by navigation, so read the form before it goes)
  const handleForm = (form) => {
    submitted = true;
    if (!armed || !(form instanceof HTMLFormElement)) { send({ type: "submit" }); return; }
    try {
      const params = new URLSearchParams();
      for (const [k, v] of new FormData(form).entries()) if (typeof v === "string") params.append(k, v);
      const action = new URL(form.getAttribute("action") || location.href, location.href);
      const method = (form.getAttribute("method") || "get").toLowerCase();
      if (method === "get") { action.search = params.toString(); check(action.href, null, "form"); }
      else check(action.href, params, "form");
    } catch {}
    send({ type: "submit" });
  };
  window.addEventListener("submit", (e) => handleForm(e.target), true);
  const _formSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () { try { handleForm(this); } catch {} return _formSubmit.apply(this, arguments); };

  // A click on a button also counts as "pressed submit" (single-page apps often skip the form event)
  window.addEventListener("click", (e) => {
    try {
      const t = e.target instanceof Element ? e.target.closest('button, input[type="submit"], input[type="button"], [role="button"]') : null;
      if (t && !submitted) { submitted = true; send({ type: "submit" }); }
    } catch {}
  }, true);
  disguiseAll(__snap);
})();
