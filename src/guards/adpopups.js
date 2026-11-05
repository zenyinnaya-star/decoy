// Ad blocker: pop-up ads. A page opening a window with no click or tap is an ad (or worse). Only active when the ad blocker is ON.
export default {
  id: "adpopups",
  targets: () => [() => [window, "open"]],
  install(ctx) {
    ctx.patch(window, "open", (o) => function () {
      try {
        if (ctx.opt("adblock") && !ctx.gesture()) {
          ctx.allowOnce("Decoy blocked a pop-up", "This page tried to open a new window without you clicking anything.", () => o.apply(window, arguments), "Keep blocked");
          return null;
        }
      } catch {}
      return o.apply(this, arguments);
    });
  },
};
