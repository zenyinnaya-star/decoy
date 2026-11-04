// D3: permission prompts nobody clicked for (notifications, location, camera/mic, clipboard read, screen share).
import { Burst } from "../guard-rules.js";

export default {
  id: "permissions",
  targets: () => [
    () => [Clipboard.prototype, "readText"], () => [Clipboard.prototype, "read"],
    () => [MediaDevices.prototype, "getUserMedia"], () => [MediaDevices.prototype, "getDisplayMedia"],
    () => [Notification, "requestPermission"], () => [Geolocation.prototype, "getCurrentPosition"], () => [Geolocation.prototype, "watchPosition"],
  ],
  install(ctx) {
    const deferred = new Burst(120000);
    const NAMES = { geo: "your location", cam: "your camera or microphone", notif: "to send notifications", clip: "to read your clipboard", screen: "to record your screen" };
    // run(): call the real API. deny(): act like the user said no.
    function guarded(kind, permName, run, deny) {
      if (ctx.gesture() || !ctx.on("permissions", true)) return run();
      const decide = (state) => {
        if (state === "granted" || state === "denied") return run(); // already decided, nothing to protect
        ctx.emit("perm-prompt");
        if (deferred.hit() >= 3) ctx.emit("perm-repeat");
        ctx.chip("This page wants " + NAMES[kind], "It asked without you clicking anything, so Decoy held it back.", [["Block", deny, true], ["Allow", run]]);
        return undefined;
      };
      if (permName && navigator.permissions?.query) {
        return navigator.permissions.query({ name: permName }).then((s) => decide(s.state), () => decide("prompt")).then((v) => v);
      }
      return decide("prompt");
    }
    const wrapP = (proto, fn, kind, permName, denyErr) => {
      if (!proto) return;
      ctx.patch(proto, fn, (o) => function () {
        const self = this, a = arguments;
        return new Promise((res, rej) => {
          const out = guarded(kind, permName, () => { try { return Promise.resolve(o.apply(self, a)).then(res, rej); } catch (e) { rej(e); } }, () => rej(denyErr()));
          if (out && out.then) out.then(() => {});
        });
      });
    };
    const notAllowed = () => new DOMException("Permission denied", "NotAllowedError");
    if (typeof MediaDevices !== "undefined") { wrapP(MediaDevices.prototype, "getUserMedia", "cam", "camera", notAllowed); wrapP(MediaDevices.prototype, "getDisplayMedia", "screen", null, notAllowed); }
    if (typeof Clipboard !== "undefined") { wrapP(Clipboard.prototype, "readText", "clip", "clipboard-read", notAllowed); wrapP(Clipboard.prototype, "read", "clip", "clipboard-read", notAllowed); }
    if (typeof Notification !== "undefined" && Notification.requestPermission) {
      ctx.patch(Notification, "requestPermission", (orig) => { const o = orig.bind(Notification); return function (cb) {
        return new Promise((res) => {
          const fin = (v) => { try { cb && cb(v); } catch {} res(v); };
          const out = guarded("notif", "notifications", () => o().then(fin, () => fin("default")), () => fin("denied"));
          if (out && out.then) out.then(() => {});
        });
      }; });
    }
    if (typeof Geolocation !== "undefined") {
      for (const fn of ["getCurrentPosition", "watchPosition"]) {
        ctx.patch(Geolocation.prototype, fn, (o) => function (ok, err, opts) {
          const self = this;
          const out = guarded("geo", "geolocation", () => o.call(self, ok, err, opts), () => { try { err && err({ code: 1, message: "User denied Geolocation", PERMISSION_DENIED: 1 }); } catch {} });
          if (out && out.then) out.then(() => {});
          return 0;
        });
      }
    }
  },
};
