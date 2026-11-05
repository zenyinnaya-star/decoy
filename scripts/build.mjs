import { build } from "esbuild";
import { cpSync, rmSync, readFileSync, writeFileSync } from "fs";
rmSync("dist", { recursive: true, force: true });
await build({
  entryPoints: ["src/content.js", "src/bridge.js", "src/watcher.js", "src/guard.js", "src/ads.js", "src/background.js", "src/popup.js"],
  bundle: true, minify: true, format: "iife", target: "chrome111", outdir: "dist", logLevel: "info",
  define: { __TEST__: String(process.env.DECOY_TEST === "1"), __DEV__: String(process.env.DECOY_DEV === "1") },
});
cpSync("static", "dist", { recursive: true });
import { adRules } from "../src/ads-data.js";
writeFileSync("dist/ads.json", JSON.stringify(adRules()));

// Heavy permissions are OPTIONAL in the real build (turned on from the popup). The e2e build (DECOY_TEST=1) makes them required so tests can run unattended.
const m = JSON.parse(readFileSync("dist/manifest.json", "utf8"));
const OPT = ["downloads", "notifications"];
if (process.env.DECOY_TEST === "1") m.permissions = [...new Set([...m.permissions, ...OPT])];
else { m.permissions = m.permissions.filter((p) => !OPT.includes(p)); m.optional_permissions = OPT; }
writeFileSync("dist/manifest.json", JSON.stringify(m, null, 2));
writeFileSync("dist/build.json", JSON.stringify({ date: new Date().toISOString().slice(0, 10), stamp: Date.now(), test: process.env.DECOY_TEST === "1" }));
