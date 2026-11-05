// npm run dev: rebuild on every change, and the dev build reloads itself in Chrome. Test builds only.
import { watch } from "fs";
import { spawnSync } from "child_process";
let t = null;
const run = () => { const r = spawnSync("node", ["scripts/build.mjs"], { stdio: "inherit", env: { ...process.env, DECOY_DEV: "1" } }); if (r.status) console.log("build failed, waiting for the next change"); };
run();
console.log("Watching src/ and static/. Load the dist folder once at chrome://extensions; it reloads itself after this.");
for (const d of ["src", "static"]) watch(d, { recursive: true }, () => { clearTimeout(t); t = setTimeout(run, 300); });
