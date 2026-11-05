// Ad blocker, behaviour part: pop-up ads, pop-unders, click hijacks and forced redirects. Only active when the ad blocker is ON.
// Never blocks something you asked for: a real link click, or a window opened by a real click on a button, still works.
import { AD_DOMAINS } from "../ads-data.js";

const ADS = new Set(AD_DOMAINS);
const hostOf = (u) => { try { return new URL(u, location.href).hostname.toLowerCase(); } catch { return ""; } };
const isAdHost = (h) => { const p = h.split("."); for (let i = 0; i < p.length - 1; i++) if (ADS.has(p.slice(i).join("."))) return true; return false; };
const isAdUrl = (u) => isAdHost(hostOf(u));
const SLD = new Set(["co", "com", "org", "net", "gov", "edu", "ac"]);
const site = (h) => { const p = h.split("."); if (p.length <= 2) return h; const n = SLD.has(p[p.length - 2]) && p[p.length - 1].length === 2 ? 3 : 2; return p.slice(-n).join("."); };
const crossSite = (u) => { const h = hostOf(u); return !!h && site(h) !== site(location.hostname); };

// An invisible layer laid over the page so any click anywhere opens an ad.
function hijackLayer(el) {
  try {
    if (!(el instanceof HTMLElement) || /^(A|BUTTON|INPUT|SELECT|TEXTAREA|LABEL|VIDEO|CANVAS|IMG|IFRAME)$/.test(el.tagName)) return false;
    const cs = getComputedStyle(el);
    if (cs.position !== "fixed" && cs.position !== "absolute") return false;
    const r = el.getBoundingClientRect();
    if (r.width < innerWidth * 0.8 || r.height < innerHeight * 0.8) return false;
    const clear = parseFloat(cs.opacity) < 0.1 || /rgba\(0, 0, 0, 0\)|transparent/.test(cs.backgroundColor) && !cs.backgroundImage.startsWith("url");
    return clear && !el.textContent.trim() && !el.querySelector("img,video,canvas,iframe,svg,input,button,a") && el.getAttribute("role") !== "dialog";
  } catch { return false; }
}

export default {
  id: "adpopups",
  targets: () => [() => [window, "open"]],
  install(ctx) {
    let allowedNav = "";
    ctx.patch(window, "open", (o) => function (url) {
      try {
        if (ctx.opt("adblock") && (!ctx.gesture() || (url && isAdUrl(String(url))))) {
          const args = arguments;
          ctx.allowOnce("Decoy blocked a pop-up", "This page tried to open another window" + (ctx.gesture() ? " to an ad site." : " without you clicking anything."), () => o.apply(window, args));
          return null;
        }
      } catch {}
      return o.apply(this, arguments);
    });

    // Clicks that an ad would hijack: links to ad networks, and invisible full-page layers.
    document.addEventListener("click", (e) => {
      try {
        if (!ctx.opt("adblock") || !e.isTrusted) return;
        const a = e.target.closest && e.target.closest("a[href]");
        if (a && isAdUrl(a.href)) {
          e.preventDefault(); e.stopImmediatePropagation();
          ctx.chip("Decoy stopped an ad link", "That link goes to an ad network, not the page it looks like.", [["OK", () => {}, true], ["Open it", () => { allowedNav = a.href; window.open(a.href, "_blank", "noopener"); }]]);
        } else if (hijackLayer(e.target)) {
          e.preventDefault(); e.stopImmediatePropagation(); e.target.style.setProperty("display", "none", "important");
          ctx.chip("Decoy removed an invisible layer", "Something invisible was covering this page so any click would open an ad. Your click went nowhere; click again.", [["OK", () => {}, true]]);
        }
      } catch {}
    }, true);

    // Forced redirects: the page sends you to another site by itself, with no click behind it.
    try {
      if (window === window.top && window.navigation) {
        window.navigation.addEventListener("navigate", (e) => {
          try {
            if (!ctx.opt("adblock") || !e.cancelable || e.userInitiated || e.hashChange || e.downloadRequest) return;
            if (e.navigationType !== "push" && e.navigationType !== "replace") return;
            const to = e.destination.url;
            if (!crossSite(to) || to === allowedNav) return;
            if (!isAdUrl(to) && ctx.gesture()) return; // a script reacting to your click (sign-in, checkout): leave it
            e.preventDefault();
            ctx.allowOnce("Decoy stopped a redirect", `This page tried to send you to ${hostOf(to)} on its own.`, () => { allowedNav = to; location.href = to; }, "Stay here");
          } catch {}
        });
      }
    } catch {}
  },
};
