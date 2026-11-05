// Ad blocker, page part (ISOLATED, document_start): hides leftover empty ad slots when the blocker is ON.
// The network blocking itself is a declarativeNetRequest ruleset (dist/ads.json), switched on from the popup.
import { AD_CSS } from "./ads-data.js";
(async () => {
  try {
    const { adblock = false, paused = [] } = await chrome.storage.local.get(["adblock", "paused"]);
    if (!adblock || paused.includes(location.hostname)) return;
    const st = document.createElement("style");
    st.textContent = AD_CSS;
    (document.head || document.documentElement).append(st);
  } catch {}
})();
