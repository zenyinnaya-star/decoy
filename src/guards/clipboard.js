// D2: ClickFix commands and silent crypto-address swaps.
import { clipboardRisk } from "../guard-rules.js";

export default {
  id: "clipboard",
  targets: () => [() => [Clipboard.prototype, "writeText"], () => [DataTransfer.prototype, "setData"], () => [Document.prototype, "execCommand"]],
  install(ctx) {
    const judge = (text) => (ctx.on("clipboard") ? clipboardRisk(text, { gesture: ctx.gesture(), lure: ctx.lure }) : null);
    const blocked = (risk, allow) => ctx.allowOnce("Decoy blocked a copy", `${risk.label}. Don't paste anything from a website into Run, Terminal or PowerShell.`, allow);

    if (typeof Clipboard !== "undefined") ctx.patch(Clipboard.prototype, "writeText", (orig) => function (text) {
      let risk = null; try { risk = judge(text); } catch {}
      if (!risk) return orig.apply(this, arguments);
      ctx.emit(risk.kind);
      const self = this; blocked(risk, () => orig.call(self, text).catch(() => {}));
      return Promise.resolve();
    });
    if (typeof DataTransfer !== "undefined") ctx.patch(DataTransfer.prototype, "setData", (orig) => function (type, val) {
      let risk = null; try { if (/^text(\/plain)?$/i.test(type)) risk = judge(val); } catch {}
      if (!risk) return orig.apply(this, arguments);
      ctx.emit(risk.kind); blocked(risk, () => { try { navigator.clipboard.writeText(String(val)); } catch {} });
    });
    ctx.patch(Document.prototype, "execCommand", (orig) => function (cmd) {
      try {
        if (/^(copy|cut)$/i.test(cmd)) {
          const a = document.activeElement; let sel = "";
          if (a && typeof a.value === "string" && a.selectionStart != null) sel = a.value.slice(a.selectionStart, a.selectionEnd);
          sel = sel || String(getSelection());
          const risk = judge(sel);
          if (risk) { ctx.emit(risk.kind); blocked(risk, () => { try { navigator.clipboard.writeText(sel); } catch {} }); return false; }
        }
      } catch {}
      return orig.apply(this, arguments);
    });
  },
};
