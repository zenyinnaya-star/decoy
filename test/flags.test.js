import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { FLAGS, GUARD_KINDS, make, explain, has } from "../src/flags.js";
import { computeScore } from "../src/score.js";

test("every flag has a valid tier, weight, label and a plain-English reason", () => {
  for (const [id, f] of Object.entries(FLAGS)) {
    assert.ok(["strong", "weak"].includes(f.tier), id);
    assert.ok(f.weight >= 0 && f.label && f.why && f.src, id);
  }
});

test("every id raised anywhere in src/ is in the table", () => {
  const src = ["scanner", "assess", "background", "protect", "guard"].map((n) => fs.readFileSync(new URL(`../src/${n}.js`, import.meta.url), "utf8")).join("\n");
  const ids = new Set([...src.matchAll(/\badd\("([a-z-]+)"/g)].map((m) => m[1]));
  for (const m of src.matchAll(/flags\.push\(\{ id: "([a-z-]+)"/g)) ids.add(m[1]);
  for (const m of src.matchAll(/report\("([a-z-]+)"\)/g)) ids.add(m[1]);
  assert.ok(ids.size > 25);
  for (const id of ids) assert.ok(has(id), `missing from flags.js: ${id}`);
});

test("guard kinds are derived from the table", () => {
  assert.equal(GUARD_KINDS["clipboard-command"].weight, FLAGS["clipboard-command"].weight);
  assert.ok(!("ip" in GUARD_KINDS));
});

test("make() and explain() work and feed the scorer", () => {
  const flags = [make("lookalike", { label: 'Address imitates "paypal"' }), make("tld")];
  const r = computeScore(flags);
  assert.ok(r.score > 0);
  const ex = explain(flags);
  assert.equal(ex[0].id, "lookalike");
  assert.ok(ex[0].why.length > 10);
  assert.match(ex[0].label, /paypal/);
});

test("crowd flag counts like a list hit: it can reach Likely scam on its own", () => {
  assert.ok(has("crowd"));
  assert.ok(computeScore([make("crowd")]).score >= 70);
  assert.ok(computeScore([make("lookalike")]).score < 70);
});
