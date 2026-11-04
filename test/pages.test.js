import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "./helpers.js";

const RANK = { "Looks fine": 0, "Well-known site": 0, "Government / education site": 0, "Trusted by you": 0, "A bit off": 1, "Sketchy": 2, "Likely scam": 3 };
const rank = (l) => RANK[l];
const log = (r) => console.log(`    ${r.level} (${r.score}): ${r.flags.map((f) => `${f.id}+${f.weight}`).join(", ") || "-"}`);
const atLeast = (r, l) => log(r) || assert.ok(rank(r.level) >= rank(l), `${r.level} (${r.score}) < ${l}: ${r.flags.map((f) => f.id)}`);
const atMost = (r, l) => log(r) || assert.ok(rank(r.level) <= rank(l), `${r.level} (${r.score}) > ${l}: ${r.flags.map((f) => `${f.id}:${f.weight}`)}`);

test("PayPal phishing page -> Likely scam", () => {
  const r = evaluate("https://paypal-account-verify.com/signin", `
    <title>PayPal - Log In</title>
    <p>Your account has been limited. Verify your account immediately to restore access.</p>
    <form action="https://collect-data.ru/p.php"><input type="email" name="email"><input type="password" name="pw"></form>`, { ageDays: 5 });
  atLeast(r, "Likely scam");
});

test("Typo-squat login (arnazon) -> at least Sketchy", () => {
  const r = evaluate("https://arnazon.com/ap/signin", `<title>Sign-In</title>
    <form action="/login"><input type="email"><input type="password"></form><a href="/privacy">Privacy</a>`, { ageDays: 40 });
  atLeast(r, "Sketchy");
});

test("Fake 90%-off shop asking for crypto -> at least Sketchy", () => {
  const r = evaluate("https://nike-outlet-sale.shop/checkout", `<title>Checkout</title>
    <p>Mega clearance: 90% off everything! Only 3 left in stock. Act now! Last chance!</p>
    <p>We accept payment in Bitcoin or USDT for faster shipping.</p>
    <input name="cardnumber" autocomplete="cc-number"><input name="cvc">`, { ageDays: 12 });
  atLeast(r, "Sketchy");
});

test("Real small shop (not famous) -> Looks fine", () => {
  const r = evaluate("https://maplecandleco.ca/checkout", `<title>Maple Candle Co. - Checkout</title>
    <form action="https://api.stripe.com/v1/tokens"><input autocomplete="cc-number" name="cardnumber"><input name="cvc"></form>
    <p>30-day refund policy. Questions? <a href="/contact">Contact us</a></p><a href="/privacy">Privacy policy</a>`, { ageDays: 2100 });
  atMost(r, "Looks fine");
});

test("GitHub login -> Well-known site", () => {
  const r = evaluate("https://github.com/login", `<title>Sign in to GitHub</title>
    <form action="/session"><input name="login"><input type="password"></form>`);
  assert.equal(r.trusted, true);
  atMost(r, "Looks fine");
});

test("News article mentioning Apple + 'limited time' -> Looks fine", () => {
  const r = evaluate("https://smalltownnews.net/tech/apple-event", `<title>Apple unveils new iPhone</title>
    <p>The limited time trade-in deal ends Friday. Act now, says Apple.</p>`, { ageDays: 900 });
  atMost(r, "Looks fine");
});

test("Brand-new blog with no forms -> not worse than A bit off", () => {
  const r = evaluate("https://my-new-recipes.com/", `<title>Recipes</title><p>Welcome!</p>`, { ageDays: 6 });
  atMost(r, "Looks fine");
});

test("Plain-HTTP login page -> at least A bit off", () => {
  const r = evaluate("http://forum.example-club.org/login", `<title>Login</title>
    <form><input name="user"><input type="password"></form><a href="/terms">Terms</a>`, { ageDays: 3000 });
  atLeast(r, "A bit off");
});

test("Login form posting to Google/Okta SSO is not flagged as cross-site", () => {
  const r = evaluate("https://intranet-tools.io/login", `<title>Login</title>
    <form action="https://acme.okta.com/login"><input type="password"></form><a href="/privacy">Privacy</a>`, { ageDays: 2000 });
  assert.ok(!r.flags.some((f) => f.id === "xform"));
});

// ---- A4: tricky legit pages that must NOT be flagged -------------------------------------------

test("Credit union login with security notices -> Looks fine", () => {
  const r = evaluate("https://northvalleycu.ca/login", `<title>Member Login | North Valley Credit Union</title>
    <p>We will never ask you to verify your account immediately by email or text.</p>
    <p>If you ever see unusual sign-in activity, call us. We do not ask you to confirm your billing details by email.</p>
    <form action="/session"><input name="member"><input type="password" name="pw"></form>
    <a href="/privacy">Privacy</a> <a href="/contact">Contact</a>`, { ageDays: 5000 });
  atMost(r, "Looks fine");
});

test("University login with scare wording (.edu) -> skipped, Government / education site", () => {
  const r = evaluate("https://login.example-uni.edu/", `<title>Student Portal</title>
    <p>Your account has been locked. Verify your account immediately.</p>
    <form action="/sso"><input type="password"></form>`, { ageDays: 10 });
  assert.equal(r.level, "Government / education site");
});

test("Government portal (.gov.uk, .gc.ca) -> skipped", () => {
  for (const u of ["https://portal.example.gov.uk/signin", "https://my.example.gc.ca/login", "https://sso.cs.example.ac.uk/"]) {
    const r = evaluate(u, `<title>Sign in</title><form action="https://other-vendor.com/x"><input type="password"></form>`, { ageDays: 5 });
    atMost(r, "Looks fine");
  }
});

test("Article ABOUT phishing (no login form) -> Looks fine", () => {
  const r = evaluate("https://securityblog.example.org/phishing-tips", `<title>How to spot phishing</title>
    <p>Scam emails say: "Your account has been suspended. Verify your account immediately." Also "Congratulations, you have won!"</p>
    <p>Sellers pushing 90% off, act now, last chance, and payment by bitcoin or gift cards are red flags.</p>`, { ageDays: 30 });
  atMost(r, "Looks fine");
});

test("Established crypto exchange with a card form -> Looks fine", () => {
  const r = evaluate("https://smallcoinexchange.com/deposit", `<title>Deposit</title>
    <p>Payment methods: bank card, bitcoin, crypto transfer, wire transfer.</p>
    <input name="cardnumber" autocomplete="cc-number"><a href="/privacy">Privacy</a><a href="/contact">Contact us</a>
    <p>Refund policy applies.</p>`, { ageDays: 300 });
  atMost(r, "Looks fine");
});

test("Brand-new but honest local shop (has privacy, contact, refund) -> Looks fine", () => {
  const r = evaluate("https://pinecreekbakery.ca/checkout", `<title>Checkout</title>
    <input name="cardnumber" autocomplete="cc-number"><input name="cvc">
    <a href="/privacy">Privacy</a><a href="/contact">Contact us</a><p>Refunds within 14 days.</p>`, { ageDays: 20 });
  atMost(r, "Looks fine");
});

test("3-year-old store with a Black Friday sale -> Looks fine", () => {
  const r = evaluate("https://cozyhomegoods.com/checkout", `<title>Checkout</title>
    <p>Up to 80% off sale! Limited time only. Last chance to save!</p>
    <input name="cardnumber" autocomplete="cc-number">
    <a href="/privacy">Privacy</a><a href="/contact">Contact us</a><p>Free returns.</p>`, { ageDays: 1100 });
  atMost(r, "Looks fine");
});

test("Page title mentioning a brand mid-sentence is not impersonation", () => {
  const r = evaluate("https://calendar-sync.io/login", `<title>Connect your Google Calendar - Login</title>
    <form action="/s"><input type="password"></form><a href="/privacy">Privacy</a>`, { ageDays: 900 });
  assert.ok(!r.flags.some((f) => f.id === "brandmismatch"));
});

// ---- A1: weak flags alone can never reach Sketchy ----------------------------------------------

test("Pile of weak flags only -> capped at A bit off", () => {
  const r = evaluate("http://cheap-stuff.xyz/login", `<title>Login</title>
    <form action="/in"><input type="password"></form>`, { ageDays: 3 });
  assert.equal(r.level, "A bit off");
  assert.equal(r.capped, "weak-only");
  assert.ok(r.score <= 35);
});

test("One strong flag + many weak flags -> at most Sketchy, never Likely scam", () => {
  const r = evaluate("https://secure-signin.xyz/account", `<title>Account</title>
    <form action="https://collector.test/p"><input type="password"></form>`, { ageDays: 2 });
  assert.ok(r.strong === 1, `strong=${r.strong}`);
  assert.ok(r.score <= 69);
});

test("Fake shop pattern (new + payment form + pressure + crypto) is Sketchy via the combo flag", () => {
  const r = evaluate("https://nike-outlet-sale.shop/checkout", `<title>Checkout</title>
    <p>90% off! Only 2 left in stock. Act now. We accept payment in bitcoin.</p>
    <input name="cardnumber" autocomplete="cc-number">`, { ageDays: 9 });
  assert.ok(r.flags.some((f) => f.id === "newshop"));
  atLeast(r, "Sketchy");
});
