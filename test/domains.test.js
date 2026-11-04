import { test } from "node:test";
import assert from "node:assert/strict";
import punycode from "punycode/punycode.es6.js";
import { domainIds } from "./helpers.js";

const BRAND_FLAGS = ["brandlure", "lookalike", "subbrand", "punycode"];
const flagged = (h) => domainIds(h).some((id) => BRAND_FLAGS.includes(id));

const SCAMS = [
  "paypa1.com", "paypal-secure-login.com", "secure-paypal-verify.xyz", "amaz0n.com", "arnazon.com",
  "rnicrosoft.com", "g00gle-support.com", "appleid-verify.com", "appleidverify.com", "netflix-billing-update.com",
  "netflixbilling.com", "paypal.com.verify-account.xyz", "login.microsoft.com-secure.top",
  "coinbase-wallet-restore.app", "metamask-recovery.io", "canadapost-delivery.info", "interac-etransfer-claim.com",
  "instagram-help-center.net", "faceb00k.com", "wellsfargo-alert.com", "linkedln.com", "dlscord.gift",
  "steamcommunlty.com", "amazon-customer-care.org", "icloud-unlock.com", "binance-airdrop.top",
  punycode.toASCII("pаypal.com"), // Cyrillic а
  punycode.toASCII("аррӏе.com"), // all Cyrillic look-alikes
];

const LEGIT = [
  "paypal.com", "purchase.com", "applebees.com", "booking.com", "secure-hotel-booking.com",
  "finance.yahoo.com", "mobile.de", "abc-cooking.jp", "github.io", "someone.github.io", "support.apple.com",
  "chase.com", "chasebank.org", "targetpractice.com", "applecart.co.uk", "googleapis.com", "accounts-google-com.translate.goog",
  "localhost", "192.168.1.1", "my-nas.local", "steamboat.com", "upsidedown.com", "bestbuyers.org",
  punycode.toASCII("яндекс.рф"), punycode.toASCII("東京.jp"), punycode.toASCII("münchen.de"), punycode.toASCII("çiçek.com.tr"),
];

for (const h of SCAMS) test(`catches ${h}`, () => assert.ok(flagged(h), `${h} -> ${domainIds(h)}`));
for (const h of LEGIT) test(`leaves alone ${h}`, () => assert.ok(!flagged(h), `${h} -> ${domainIds(h)}`));
