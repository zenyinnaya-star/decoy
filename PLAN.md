# Decoy plan

Browser extension that (1) scores a page for scam signals and (2) lets you test a form with a dummy identity and watch where the data goes.

## Status (v0.6)

| Item | State |
|---|---|
| A1 two-tier flags + caps | **Done** |
| A2 gate text checks on login/card | **Done** (plus a "we will NEVER ask you to verify..." negation guard) |
| A3 trusted suffixes, age dampening | **Done** (`.gov .edu .mil .ac.* .gc.ca`; 2-year-old domains halve weak flags) |
| A4 regression fixtures | **Done** (11 tricky legit pages in `test/pages.test.js`) |
| B watcher + canary identity + verdict card | **Done** (95 unit tests + real-Chromium e2e on 4 pretend sites + local testbed) |
| D2 clipboard guard, D3 permission guard, D6 scareware guard | **Done** (v0.4, `src/guard.js`, e2e in real Chromium with bad + legit fixtures) |
| D1, D4, D5, D7, D8, D9, D10, D11, D12, D13, D14, D15, D16 | **Done** (v0.5, `src/protect.js`, e2e in real Chromium) |
| Auto-scan + toast + badge (A7) | **Done** (modes: background / ask / off; no network) |
| A5 real-page crawl + "report wrong score" | Next |
| B2 delayed canary inbox | Next |
| A6 known-bad feed | Planned |
| A7 toolbar badge / quieter UI | **Done** (with auto-scan) |
| Phase C polish | Planned |

Still open: A5 real-page crawl (needs the live web, run on your machine), A6 known-bad feed (network), B2 delayed canary inbox (mail.tm network), Phase C polish.

Known gaps in the dummy test: cross-origin iframes the page builds itself after load, service-worker traffic, and sites that grab a fresh `fetch` from an iframe can slip past the watcher. Server-side forwarding is invisible by design (the card says so).

---

## Principles
1. A wrong "scam" label on a real site costs more than a miss. The score needs evidence, not a pile of hints.
2. Decoy never submits a form for you. You click the site's own button.
3. Only fake data is ever typed. Card = the 4242 test number. Nothing real leaves the browser.
4. Measure before shipping. Every change re-runs the false-positive checks.

---

## Phase A: no false alarms

| # | What | Why |
|---|---|---|
| A1 | **Two tiers of flags.** Strong: brand impersonation, password/card posted to another site, scare text + login form, known-bad list hit, (Phase B) data grabbed. Weak: new domain, odd TLD, no privacy link, HTTP, pressure text, discounts. Weak-only caps at "A bit off" (~35). "Sketchy" needs 1+ strong flag. "Likely scam" needs a list hit or 2 strong flags. | One bad hint can't condemn a real site |
| A2 | **Gate text checks on a login/card field.** Scare, pressure, discount, crypto/gift-card text only count if the page also asks for a password or card. | A news article about phishing shouldn't score |
| A3 | **More trust.** Skip page checks on `.gov .edu .mil .ac.* .gc.ca`. Halve weak flags on domains older than 2 years with HTTPS. Keep "I trust this site". | Real institutions and old sites |
| A4 | **Regression fixtures** (run in `npm test`): bank login, university, gov site, SaaS single sign-on, crypto exchange, scam-awareness article, brand-new local shop, forum. Fail if any goes above "Looks fine". Domain sweep must stay under 0.03%. | Locks the gains in |
| A5 | **Real-page crawl.** `npm run crawl` (run on your machine, sandbox has no web): opens ~500 random real sites, prints which got any flag and why. Target: under 1% with any flag, ~0 above "A bit off". Plus a "Report wrong score" button that copies flags + domain only. | Domain tests don't cover page checks |
| A6 | **Known-bad feed.** OpenPhish / URLhaus (free), optional Google Safe Browsing key. | Real evidence for the red label |
| A7 | **Quieter UI.** Toolbar badge (green/yellow/red) on every page. Warning banner only at 70+. Wording "warning signs found" unless a feed backs it. | Fewer scary moments |

---

## Phase B: dummy test ("Test with dummy")

Goal: on any form page, fill a unique fake identity, watch every outgoing request, and tell you (a) where the data went and (b) whether the site behaves like a legit one.

### Flow
1. You press **Test with dummy** in the popup (one site at a time, never automatic).
2. Decoy builds a **canary identity** for this site: random email (`dc-k7x2qp@…`), random password, random phone, plausible name, card 4242 4242 4242 4242. The email/password/phone contain unique tokens we can recognise in traffic.
3. It fills the form and **arms the watcher**. A small overlay says "Watching. Submit the form yourself."
4. The watcher records every request that contains a canary value, then you submit.
5. A **verdict card** shows what happened and combines it with the Phase A score.

### The watcher (what we can see)
A script injected into the page itself (`"world": "MAIN"`, all frames) wraps:
`fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `WebSocket.send`, `HTMLFormElement.submit` / submit events, and image-pixel requests.
For each request it checks URL + body for the canary values in these forms: plain, URL-encoded, base64, hex, and **SHA-256 / MD5 of the email** (ad pixels send hashed emails).
No extra permissions needed (no `webRequest`, no broad host access beyond what the content script already has).

### What gets recorded (a "finding")
`{ type, severity, destination, via (fetch/form/beacon/...), field, beforeSubmit, time }`

### How findings are judged
| Finding | Severity |
|---|---|
| Data only goes to the site itself | OK |
| Data to a known payment / login provider (Stripe, PayPal, Okta, Google...) | OK |
| Hashed email or email to analytics / ad pixels (Meta, Google Ads, TikTok...) | Info (very common on real sites) |
| Data to a form service (Formspree, Google Forms, Mailchimp...) | Info |
| Data to an **unknown third-party domain** | Warn |
| Data to a **known grabber endpoint**: Telegram bot API, Discord webhook, Slack webhook, pastebin, webhook.site, requestbin, ngrok, `*.workers.dev`, firebaseio, raw IP address | **Strong** |
| Password or card sent to a third party | **Strong** |
| Data sent **before you pressed submit** (on typing / blur) to a third party | **Strong** (keylogger-style kit) |
| Form posts over plain HTTP | Strong |
| After submit, you are **redirected to the real brand's site** (classic phishing: grab, then bounce to paypal.com) | Strong |
| After a "login", page asks for **more** sensitive data (card, OTP, SSN, ID upload) | Warn |

### Verdict card
- **No leak seen**: data stayed with the site and known providers.
- **Be careful**: third-party recipients or odd behaviour, explained one line each.
- **Looks like a data grabber**: any Strong finding, or Phase A score 70+ plus a Warn.
- Always shows the honest limit: *"We can only see what your browser sends. A site can still pass data on from its server."*

### B2: delayed leak check (the "was it stolen later" part)
- Each canary email is unique per site and saved in a local **Canary log** (site, address, date).
- v1: use a throwaway inbox (mail.tm free API) and poll it with `chrome.alarms`. Mail from unrelated senders within 30 days = "this site shared or leaked your address".
- Option: point Decoy at your own catch-all domain instead. It never uses your real Gmail by default.
- Log stores addresses and dates only. Values typed are never kept after the test.

### Safety rules
- Explicit click per site. No background form filling, no auto-submit.
- Sites in the top-40k allowlist show "Well-known site, test not needed" with an override.
- Warn before testing: *"Real sites may create a junk account. Use a throwaway."*
- Watcher logs stay local and keep destinations + field names only.
- Never types real data, never reads your saved passwords or autofill.

### B tests (all runnable in the sandbox, no real sites)
Local test server with 4 pretend sites, driven by Playwright with the extension loaded:
1. **Honest shop**: posts to itself and to Stripe. Expect: OK.
2. **Tracker-heavy shop**: sends SHA-256 of the email to a pixel. Expect: Info only.
3. **Grabber kit**: sends keystrokes to a Telegram-style endpoint on input, posts password to another domain, then redirects to a real-brand URL. Expect: 3 Strong findings, "Looks like a data grabber".
4. **Slow leaker**: nothing visible in the browser. Expect: "No leak seen" plus the honest-limit line.

---

## Phase E: hardening (fixes for the problems list)
| Problem | Fix | State |
|---|---|---|
| Guards might break real sites | Pause per site, per-guard switches, trusted sites skip permission/alert/history guards, alert guard now needs 4 boxes in 15s, link check ignores tracking redirects (not on login pages) | **Done** |
| False alarms | Pop-ups only at Sketchy+, "Report wrong score" button, crawl script (`npm run crawl`) | **Done**; run the crawl on a real connection next |
| False sense of safety | "Looks fine" text now says it is not a guarantee | **Done** |
| Pages detect the hooks | Wrapped functions and `Function.prototype.toString` print as native | **Done** |
| Performance | Benchmark (`npm run e2e:perf`): ~+100 ms on a 3,000-element page | **Measured** |
| Permissions / privacy | downloads + notifications optional; age lookup opt-in; list-age notice | **Done** |
| Worker restarts, accessibility | Retry on send; alert/dialog roles + focus | **Done** |
| Iframes/workers built by the page, service-worker traffic | Hook contentWindow + Worker constructor; optional Deep watch via webRequest | Planned |
| Server-side forwarding | B2 throwaway inbox | Planned (needs network) |
| Other-extension conflicts, Firefox | Test against common blockers; port | Planned |

## Phase D: active protection
Phases A and B say something is off. These make Decoy act, without breaking Principle 2 (never submits for you) or Principle 1 (strong evidence only).

Rules: only block or delay, never submit or fill real data. Every action has "Allow this once". Auto-actions only on Strong evidence; weak flags just show a badge. Local only; log domain + flag name at most.

| # | Feature | Action | Tier |
|---|---|---|---|
| D1 | Lookalike domain guard (punycode, mixed script, edit distance <=2 to top brands) | Interstitial "This looks like paypal.com. Go there instead?" | Strong with login/card form, else Weak |
| D2 | Clipboard guard (ClickFix commands, silent crypto swap) | Block write + chip | Strong. **Done** |
| D3 | Permission-prompt guard (notifications, geo, camera/mic, clipboard-read without a click) | Defer, tap to allow | Weak, Strong if repeated. **Done** |
| D4 | Download guard (exec files from low-trust domains, no gesture) | Warn, offer cancel | Strong for exec on new domain |
| D5 | Clickjacking + browser-in-the-browser detector | Outline overlay, warn | Strong with password field |
| D6 | Scareware / lock-in guard (alert loops, history trap) | Stop dialogs, "Close this tab" | Strong on behaviour. **Done** |
| D7 | Checkout skimmer watch (new script hosts on card pages) | Card | Strong if it reads card fields |
| D8 | Session-replay notice (Hotjar, FullStory, Clarity on password/card pages) | Info line | Info |
| D9 | Submit speed bump (3s confirm on Strong pages) | Confirm, you still click | Uses score |
| D10 | OAuth consent checker (Google/Microsoft/GitHub scopes) | Plain-English banner | Warn / Strong for broad scopes from unverified app |
| D11 | Link-mismatch + short-link check | Tooltip + context menu | Strong on mismatch |
| D12 | Fake-shop check at checkout (3+ signals + checkout form) | Card | Most false-positive-prone |
| D13 | Mixed-content / HTTP guard | Warn before typing a password | Strong for form |
| D14 | Paste a link or message to pre-check | Result card | n/a |
| D15 | "I already entered something" recovery checklist | Checklist + reminder | n/a |
| D16 | Optional tracker blocking (declarativeNetRequest, off by default) | Popup toggle | n/a |

Build order: (1) D2, D3, D5, D6 MAIN-world wrappers -> (2) D1, D11, D13 -> (3) D9, D15 -> (4) D7, D8, D10, D12 (fixtures first) -> (5) D4, D14, D16.
Tests: each feature gets a bad fixture and a look-alike-but-legit fixture in the testbed (e.g. D2 fires on "paste into Run", not on a docs "Copy code" button). Domain sweep and A4 pages must stay at "Looks fine".

## Phase C: polish
Fill handles dropdowns, date pickers, split card fields, same-origin iframes. Disposable-email option. Persona saved per site. Tests for `scan()` / `computeScore()` on more fixtures. Firefox port. Store listing (icons, screenshots, GIF), privacy policy ("nothing leaves your browser except the domain-age lookup and optional feed checks"). Consider `activeTab` + on-demand injection to cut install warnings.

## Order
1. A2 → A1 → A3 → A4 (about an hour; fixes the biggest false-alarm risk)
2. B watcher + verdict card + B tests
3. A5 crawl + report button
4. B2 canary inbox
5. A6 feed → A7 UI
6. Phase C

## Open choices (defaults in bold)
- Canary email: **throwaway inbox (mail.tm)** / your own catch-all domain
- Submit: **you click the site's button** / Decoy submits after a confirm (later, optional)
- Known-bad feed: **OpenPhish + URLhaus** / add Safe Browsing (needs a Google API key)


## v0.7: Download check (done)
Post-download verdict (problem / careful / nothing suspicious), local file checker with SHA-256, file-URL access status, off switch, `download-flagged` guard kind. Not yet tested against the real file-URL read path in a normal Chrome (needs the user toggle). Not an antivirus; no cloud lookups.

## Phase F: integration foundation (in progress)
Five shared pieces first, then features plug in.
1. Flag registry: **done** (`src/flags.js`, one table of id / tier / weight / label / plain-English why; `explain()` feeds the Why-panel; `test/flags.test.js` fails if code raises an id that is not in the table).
2. Guard interface: **done** (`src/guard.js` is a loader; guards in `src/guards/{clipboard,permissions,scare,skimmer}.js` get a shared `ctx` with `emit`, `chip`, `allowOnce`, `patch` (undoable), `whenReady`). No behavior change: all unit and e2e suites pass unchanged.
3. Finding bus: next (move per-tab guard state and download results into one `findings` store in the background; popup and badge only read it).
4. Versioned storage + `migrate()`: next.
5. Optional permissions helper (`ensurePermission(name)`): next.

3. Cloud (Cloudflare Worker + D1): **built and tested locally** (`backend/`). Shared list, trusted-person invites/alerts, rate limits. Not yet deployed (needs your Cloudflare account). Next: finding bus, versioned storage, optional-permission helper; notification fallback for downloads.
