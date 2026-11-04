import test from "node:test";
import assert from "node:assert/strict";
import { linkMismatch, isShortener } from "../src/links.js";
import { parseScopes } from "../src/oauth.js";
import { extractUrls, textFlags } from "../src/precheck.js";
import { buildChecklist } from "../src/recovery.js";
import { isGhostFrame, urlBarDomain, isReplayHost, badgeFor } from "../src/protect-rules.js";
import { pageFlags, scan } from "../src/scanner.js";
import { assess } from "../src/assess.js";
import { computeScore } from "../src/score.js";
import { BRAND_DOMAINS } from "../src/brand-domains.js";
import { BRANDS } from "../src/brands.js";
import { JSDOM } from "jsdom";

const dom = (html, url = "https://shop.example.com/") => { const d = new JSDOM(html, { url }); return { doc: d.window.document, loc: d.window.location }; };

test("D11 link text vs destination", () => {
  assert.deepEqual(linkMismatch("www.paypal.com", "https://evil-pay.xyz/login", "blog.example.com"), { shown: "paypal.com", actual: "evil-pay.xyz" });
  assert.equal(linkMismatch("paypal.com", "https://www.paypal.com/signin", "x.com"), null);
  assert.equal(linkMismatch("Read our privacy policy", "https://other.com/p", "x.com"), null); // sentence
  assert.equal(linkMismatch("README.md", "https://github.com/a/b", "x.com"), null);            // a filename
  // newsletter tracking redirects are normal on ordinary pages...
  assert.equal(linkMismatch("example.com", "https://click.mailer.net/r/123", "news.test"), null);
  assert.equal(linkMismatch("example.com", "https://t.co/abc", "news.test"), null);
  assert.equal(linkMismatch("shop.com", "https://go.brand.com/r?u=https%3A%2F%2Fshop.com%2Fsale", "news.test"), null); // target carried in the URL
  // ...but NOT on a login/card page, where scammers use them too
  assert.equal(linkMismatch("example.com", "https://click.mailer.net/r/123", "news.test", { sensitive: true })?.actual, "mailer.net");
  assert.equal(linkMismatch("paypal.com", "https://evil-pay.xyz/x", "news.test")?.actual, "evil-pay.xyz");
  assert.ok(isShortener("bit.ly") && !isShortener("github.com"));
});

test("D10 OAuth scopes in plain English", () => {
  const g = parseScopes("https://accounts.google.com/o/oauth2/v2/auth?client_id=1&scope=https%3A%2F%2Fmail.google.com%2F%20email%20profile");
  assert.equal(g.provider, "Google"); assert.ok(g.broad);
  assert.match(g.scopes[0].plain, /ALL your email/);
  assert.ok(!g.scopes[1].broad);
  const m = parseScopes("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?scope=openid%20offline_access%20Mail.ReadWrite");
  assert.ok(m.broad && m.scopes.some((s) => /Keep access/.test(s.plain)));
  const gh = parseScopes("https://github.com/login/oauth/authorize?scope=repo,read:user");
  assert.ok(gh.broad);
  assert.equal(parseScopes("https://example.com/auth?scope=repo"), null);
  const basic = parseScopes("https://accounts.google.com/o/oauth2/v2/auth?scope=openid%20email%20profile");
  assert.ok(!basic.broad);
});

test("D14 pre-check pieces", () => {
  const u = extractUrls("Your parcel is held. Pay at http://post-fee.xyz/pay or visit canadapost.ca. See notes.txt");
  assert.deepEqual(u.map((x) => x.url), ["http://post-fee.xyz/pay", "http://canadapost.ca"]);
  assert.ok(textFlags("Your account has been suspended. Verify your account immediately.").some((f) => f.tier === "strong"));
  assert.ok(textFlags("Reply with your verification code to claim.").some((f) => f.id === "askcode"));
  assert.deepEqual(textFlags("Lunch at noon? I'll bring the notes."), []);
});

test("D15 recovery checklist", () => {
  const c = buildChecklist(["password", "card"]);
  assert.ok(c.some((s) => /Change that password/.test(s)) && c.some((s) => /back of your card/.test(s)));
  assert.equal(new Set(c).size, c.length);
  assert.ok(buildChecklist(["nothing"]).some((s) => /Close the tab/.test(s)));
  assert.ok(buildChecklist([]).length > 0);
});

test("D5 ghost frame and fake address bar", () => {
  const base = { opacity: 0, visibility: "visible", pointerEvents: "auto", position: "fixed", area: 500000, viewArea: 1000000, crossOrigin: true };
  assert.ok(isGhostFrame(base));
  assert.ok(!isGhostFrame({ ...base, crossOrigin: false }));       // same-site
  assert.ok(!isGhostFrame({ ...base, area: 100 }));                // tiny tracking frame
  assert.ok(!isGhostFrame({ ...base, opacity: 1 }));               // visible embed
  assert.equal(urlBarDomain("https://accounts.google.com/signin"), "accounts.google.com");
  assert.equal(urlBarDomain("Sign in with your Google account"), null);
  assert.equal(urlBarDomain("Contact us at support"), null);
});

test("D8 replay hosts and A7 badge", () => {
  assert.ok(isReplayHost("static.hotjar.com") && !isReplayHost("example.com"));
  assert.equal(badgeFor(5, null).text, "✓"); assert.equal(badgeFor(5, "popular").text, "OK");
  assert.equal(badgeFor(30).text, "?"); assert.equal(badgeFor(50).text, "!"); assert.equal(badgeFor(80).text, "!!");
});

test("D13 insecure form action and mixed content are caught, normal pages are not", () => {
  const bad = dom(`<title>Sign in</title><form action="http://collect.example.net/p"><input type=password></form><script src="http://cdn.test/a.js"></script><a href="/privacy">Privacy</a>`);
  const f = pageFlags(bad.doc, bad.loc).flags;
  assert.ok(f.some((x) => x.id === "insecureform" && x.tier === "strong"));
  assert.ok(f.some((x) => x.id === "mixed"));
  const ok = dom(`<title>Sign in</title><form action="/login"><input type=password></form><a href="/privacy">Privacy</a><script src="https://cdn.test/a.js"></script>`);
  const g = pageFlags(ok.doc, ok.loc).flags;
  assert.ok(!g.some((x) => ["insecureform", "mixed"].includes(x.id)));
});

test("D12 fake-shop needs a card form AND three signs", () => {
  const html = `<title>Deals</title><p>90% off everything! Only 2 left in stock. Act now! Pay with bitcoin or gift cards at checkout.</p><form><input name=cardnumber autocomplete=cc-number></form>`;
  const { doc, loc } = dom(html, "https://hot-deals-today.example/");
  const s = scan(doc, loc);
  const a = assess(s, { ageDays: 20 });
  assert.ok(a.flags.some((f) => f.id === "fakeshop"), a.flags.map((f) => f.id).join());
  // same page, but an established shop with refunds + contact: not flagged
  const ok = dom(`<title>Shop</title><p>Sale: 20% off.</p><a href="/returns">Returns</a><a href="/contact">Contact us</a><a href="/privacy">Privacy</a><form><input name=cardnumber autocomplete=cc-number></form>`);
  const a2 = assess(scan(ok.doc, ok.loc), { ageDays: 4000 });
  assert.ok(!a2.flags.some((f) => f.id === "fakeshop"));
  assert.equal(computeScore(a2.flags).level, "Looks fine");
});

test("D1 every brand we check has a real address to send people to", () => {
  const missing = BRANDS.filter((b) => !BRAND_DOMAINS[b]);
  assert.deepEqual(missing, []);
});
