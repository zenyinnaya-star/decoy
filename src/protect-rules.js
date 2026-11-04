// Pure helpers for the content-side protections (testable without a browser).

// D5: a see-through iframe laid over the page, so your click lands on something else.
export function isGhostFrame({ opacity, visibility, pointerEvents, position, area, viewArea, crossOrigin }) {
  return !!crossOrigin && opacity <= 0.05 && visibility !== "hidden" && pointerEvents !== "none" &&
    (position === "fixed" || position === "absolute") && viewArea > 0 && area >= 0.15 * viewArea;
}

// D5: text that is shaped like a browser address bar ("https://accounts.google.com/signin").
const BAR = /^(?:🔒\s*)?(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:\/\S*)?$/i;
export function urlBarDomain(text) {
  const t = String(text || "").trim();
  if (t.length < 6 || t.length > 90 || /\s/.test(t.replace(/^🔒\s*/, ""))) return null;
  const m = BAR.exec(t);
  return m ? m[1].toLowerCase() : null;
}

// D8: services that record your typing/mouse.
export const REPLAY = ["hotjar.com", "hotjar.io", "fullstory.com", "clarity.ms", "mouseflow.com", "luckyorange.com", "crazyegg.com",
  "smartlook.com", "inspectlet.com", "logrocket.com", "logrocket.io", "contentsquare.net", "quantummetric.com", "heapanalytics.com"];
export const isReplayHost = (host) => REPLAY.some((d) => host === d || host.endsWith("." + d));

// A7: what the toolbar badge shows.
export function badgeFor(score, trustKind) {
  if (score >= 70) return { text: "!!", color: "#d33" };
  if (score >= 45) return { text: "!", color: "#e8710a" };
  if (score >= 20) return { text: "?", color: "#c9a100" };
  return { text: trustKind ? "OK" : "✓", color: "#1e8e3e" };
}
