// Runs INSIDE the page (world: MAIN) at document_start, every frame. Guard loader.
// Each guard lives in src/guards/<name>.js and exports { id, targets(), install(ctx) }.
// Guards only block or delay. They never fill or submit anything. To add one: write the file, add it to GUARDS.
import { snapshot, disguiseAll } from "./stealth.js";
import { makeCtx } from "./guards/ctx.js";
import clipboard from "./guards/clipboard.js";
import permissions from "./guards/permissions.js";
import scare from "./guards/scare.js";
import skimmer from "./guards/skimmer.js";

const GUARDS = [clipboard, permissions, scare, skimmer];

(() => {
  const thunks = GUARDS.flatMap((g) => { try { return g.targets(); } catch { return []; } });
  const snap = snapshot(thunks); // BEFORE patching
  const ctx = makeCtx();
  for (const g of GUARDS) { try { g.install(ctx); } catch {} } // one broken guard must not take down the others
  disguiseAll(snap);
})();
