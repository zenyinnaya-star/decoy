// D7: checkout skimmers. Who is reading the card box?
import { classify } from "../destinations.js";
import { parseHost } from "../scanner.js";

export default {
  id: "skimmer",
  targets: () => [() => [HTMLInputElement.prototype, "value"]],
  install(ctx) {
    const isCard = new WeakMap(), flagged = new Set();
    const mine = parseHost(location.hostname).domain;
    ctx.patchDesc(HTMLInputElement.prototype, "value", (d) => !d.get ? d : ({
      ...d,
      get() {
        const v = d.get.call(this);
        try {
          let c = isCard.get(this);
          if (c === undefined) { c = /cc-(number|csc)|card.?n(um|o)|cardnumber|cvv|cvc/.test([this.autocomplete, this.name, this.id].join(" ").toLowerCase()); isCard.set(this, c); }
          if (c && v && !ctx.cfg.paused) {
            for (const m of (new Error().stack || "").matchAll(/https?:\/\/[^\s)]+/g)) {
              const h = new URL(m[0].replace(/:\d+:\d+$/, "")).hostname;
              if (flagged.has(h) || parseHost(h).domain === mine) continue;
              const k = classify("https://" + h + "/", location.hostname).kind;
              if (k === "grabber" || k === "suspicious") { flagged.add(h); ctx.emit("skim-read"); }
            }
          }
        } catch {}
        return v;
      },
    }));
  },
};
