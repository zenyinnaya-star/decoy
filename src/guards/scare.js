// D6: scareware. Alert-box loops and back-button traps.
import { Burst } from "../guard-rules.js";

export default {
  id: "scare",
  targets: () => [() => [window, "alert"], () => [window, "confirm"], () => [window, "prompt"], () => [History.prototype, "pushState"], () => [History.prototype, "replaceState"]],
  install(ctx) {
    const alerts = new Burst(15000); // 4+ alert boxes in 15 seconds with no click
    for (const fn of ["alert", "confirm", "prompt"]) {
      ctx.patch(window, fn, (o) => function () {
        let n = 0; try { n = ctx.gesture() || !ctx.on("scare", true) ? 0 : alerts.hit(); } catch {}
        if (n >= 4) {
          ctx.emit("scare-alert");
          if (n === 4) ctx.chip("Decoy stopped the pop-ups", "This page kept opening alert boxes. That's a scare tactic. Real warnings don't come from a web page.", [["Close this tab", ctx.closeTab, true], ["Dismiss", () => {}]]);
          return fn === "confirm" ? false : fn === "prompt" ? null : undefined;
        }
        return o.apply(this, arguments);
      });
    }
    const pushes = new Burst(2000);
    let trapped = false;
    for (const fn of ["pushState", "replaceState"]) {
      ctx.patch(History.prototype, fn, (o) => function () {
        try {
          if (pushes.hit() >= 25 && !trapped) {
            trapped = true; // settings may not have arrived yet; decide once they have
            ctx.whenReady(() => {
              if (!ctx.on("scare", true)) return;
              ctx.emit("scare-history");
              ctx.chip("This page is trapping your back button", "It is adding history entries in a loop so you can't leave.", [["Close this tab", ctx.closeTab, true], ["Dismiss", () => {}]]);
            });
          }
        } catch {}
        return o.apply(this, arguments);
      });
    }
  },
};
