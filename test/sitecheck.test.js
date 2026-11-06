import { test } from "node:test";
import assert from "node:assert/strict";
import { JSDOM } from "jsdom";
import { domFindings, headerFindings, grade, cmpVer } from "../src/sitecheck.js";
import { evaluate } from "./helpers.js";

const find = (url, html) => domFindings(new JSDOM(html, { url }).window.document, new URL(url));
const ids = (a) => a.map((f) => f.id);

test("clean https page: no findings, grade A", () => {
  const f = find("https://good.example/", `<title>x</title><p>hello</p><img src="https://good.example/a.png">`);
  assert.deepEqual(f, []); assert.equal(grade(f).letter, "A");
});
test("login over http is high", () => {
  const f = find("http://old-shop.example/login", `<form method="post"><input type="password"></form>`);
  assert.ok(ids(f).includes("login-http")); assert.equal(grade(f).letter, "D");
});
test("loopback http is not flagged", () => assert.deepEqual(find("http://localhost:3000/", `<input type="password">`), []));
test("login form with no method attribute is NOT flagged (script-submitted forms)", () => {
  assert.ok(!ids(find("https://a.example/", `<form><input type="password"></form>`)).includes("get-password"));
  const r = evaluate("https://honest-bakery.example/login", `<title>Login</title><a href="/privacy">Privacy</a><form><input type="password"></form>`);
  assert.ok(!r.flags.some((f) => f.id === "getlogin"));
});
test("password form using GET", () => assert.ok(ids(find("https://a.example/", `<form method="get"><input type="password"></form>`)).includes("get-password")));
test("https page loading http script is mixed-active (high); http image is low", () => {
  const f = find("https://a.example/", `<script src="http://cdn.example/x.js"></script><img src="http://cdn.example/i.png">`);
  assert.equal(f.find((x) => x.id === "mixed-active").sev, "high"); assert.equal(f.find((x) => x.id === "mixed-passive").sev, "low");
});
test("old library versions by file name", () => {
  const f = find("https://a.example/", `<script src="/js/jquery-1.12.4.min.js"></script><script src="/js/lodash.4.17.21.min.js"></script><script src="/jquery-3.7.1.min.js"></script>`);
  assert.deepEqual(ids(f), ["old-jquery"]);
});
test("version compare", () => { assert.equal(cmpVer("1.12.4", "3.5.0"), -1); assert.equal(cmpVer("3.5.0", "3.5.0"), 0); assert.equal(cmpVer("4.17.20", "4.17.21"), -1); });
test("secret in URL", () => assert.ok(ids(find("https://a.example/?token=abc", "<p>x</p>")).includes("secret-in-url")));
test("headers: a well-configured site is clean", () => {
  const h = { "strict-transport-security": "max-age=1", "content-security-policy": "default-src 'self'; frame-ancestors 'none'", "x-content-type-options": "nosniff" };
  assert.deepEqual(headerFindings(h, new URL("https://a.example/")), []);
});
test("headers: missing ones are low/info only, clickjacking rises on login pages", () => {
  const f = headerFindings({}, new URL("https://a.example/"), false);
  assert.ok(f.every((x) => ["low", "info"].includes(x.sev)));
  assert.equal(headerFindings({}, new URL("https://a.example/"), true).find((x) => x.id === "no-frame").sev, "medium");
});
test("old server software is reported", () => assert.ok(ids(headerFindings({ server: "Apache/2.2.15 (CentOS)" }, new URL("https://a.example/"))).includes("old-server")));

// The scam score must not move for ordinary sites that just miss headers or use an older library.
test("old library / missing headers never raise the scam score", () => {
  const r = evaluate("https://honest-bakery.example/", `<title>Bakery</title><script src="/jquery-1.12.4.min.js"></script><p>Fresh bread. <a href="/privacy">Privacy</a></p>`);
  assert.equal(r.score, 0, JSON.stringify(r.flags));
});
test("password form using GET adds only a small weak flag", () => {
  const r = evaluate("https://honest-bakery.example/login", `<title>Login</title><a href="/privacy">Privacy</a><form method="get"><input type="password"></form>`);
  assert.ok(r.flags.some((f) => f.id === "getlogin") && r.score <= 20, `${r.score}`);
});
