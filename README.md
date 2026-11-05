# Decoy

Browser extension: fills forms with fake data, scores a page for scam signals (0-100), and **tests where a form really sends your details**.

## Install (no build needed)
`chrome://extensions` -> Developer mode -> **Load unpacked** -> pick the `dist/` folder. Reload open tabs once.

## Use
- **Score:** open the popup on any page. Strong flags (red bar) drive the score; weak flags alone can never go past "A bit off".
- **Fill fake info:** stable fake persona per site. Never submits.
- **Test with dummy:** fills a one-off identity (random email/password/phone, 4242 test card), then watches every request the page makes. **You press the site's own submit button.** The card shows where the data went:
  - ok: the site itself, Stripe/PayPal/Okta...
  - info: ad pixels, form services (hashed emails to Meta etc. are normal)
  - warn: unknown third party
  - **strong:** Telegram bot / Discord webhook / paste sites / raw IP, password or card sent to a third party, data sent while you were still typing, unencrypted send, bounce to the real brand's site after capture
  - Always shows the honest limit: it only sees what the browser sends, not what the server does afterwards.

## Develop
```
npm install
npm run build     # src/ + static/ -> dist/
npm test          # 109 unit tests: scam domains caught, legit left alone, page fixtures, watcher/verdict logic
npm run e2e       # builds, loads dist/ in real Chromium, runs the dummy test against 4 pretend sites
npm run sweep     # false-positive sweep over ~360k real sites (needs data/crux.csv.gz)
```
Refresh top-sites data (monthly):
```
curl -L https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz -o data/crux.csv.gz
npm run lists && node scripts/build-words.mjs && npm run build
```

## When Decoy gets in the way (safety switches)
- **Pause Decoy on this site** (popup > More protection): all guards, toasts and stop screens off for that site. Reload the tab.
- **Per-guard switches:** clipboard, permission prompts, pop-up/back-button traps, submit speed bump, link check. Turn off just the one that breaks something.
- **Trusted sites** (top-ranked, .gov/.edu, or ones you trust) skip the permission, alert and back-button guards. Clipboard and download guards still apply everywhere.
- **Report wrong score** (popup): copies domain + flag names + score. No URL path, no page text, nothing typed. Also kept locally.
- Pop-ups only appear at "Sketchy" or worse. Smaller things show on the badge and in the popup.
- Wrapped browser functions print as native code, so a page can't easily tell it is being watched.

## Checking Decoy against real sites
```
npm run crawl -- --n 500                 # random real sites beyond the top-40k safe list (needs internet + data/crux.csv.gz)
npm run crawl -- --urls my-sites.txt     # your own list
```
Writes `crawl-report.md`: how many real sites got any flag, how many reached "A bit off" / "Sketchy", and why. Target: under 1% with any flag, about 0 at Sketchy. Anything flagged that shouldn't be: use **Report wrong score** and tune the check.
`npm run e2e:perf` compares a heavy page with and without Decoy (measured here: about +100 ms on a 3,000-element page, 38 ns to 77 ns per input read).

## Automatic scan (background notice)
Every page is checked quietly when it loads (no network, nothing leaves your browser). Pick the behaviour in the popup under **More protection**:
- **Scan in background and tell me** (default): toolbar badge (green tick / ? / ! / !!). A toast appears when something looks off, a short "checked, looks fine" on login/card pages, nothing on ordinary pages.
- **Ask me on login/card pages:** toast "This page asks for a password or card. Scan it?" with Scan now / Not now / Don't ask for this site.
- **Off.**
"Don't tell me about this site" mutes toasts for that site (70+ warnings still show).

## Active protection (Phase D)
All of it only blocks, delays or warns. It never fills or submits for you, and every block has an override.
| | What it does |
|---|---|
| D1 | Login/card page that imitates a brand: full-page stop "This looks like paypal.com" with Go there / Close tab / Allow this once |
| D2 | Clipboard guard (ClickFix commands, silent crypto swap) |
| D3 | Permission asks without a click are held until you tap Allow |
| D4 | Program files (.exe .msi .dmg .iso ...) from unfamiliar sites are paused: Cancel or Keep |
| D5 | Invisible click-jacking frames outlined; fake "browser window" with a password box flagged |
| D6 | Alert loops stopped, back-button trap flagged, Close this tab |
| D7 | Payment page: script from a data-dump host, or one reading the card box |
| D8 | Info note when a page runs session replay (Hotjar, FullStory, Clarity...) |
| D9 | 3-second confirm before submitting a password/card form on a page with strong warning signs |
| D10 | Google / Microsoft / GitHub consent screens: plain-English list of what the app can read, red if unverified |
| D11 | Links whose text says one address but go to another (dashed red); right-click a link, **Check this link with Decoy** |
| D12 | "Shop looks fake": card form plus 3 of payment-method / no refund / no contact / big discount / pressure / new domain |
| D13 | Login form that posts over plain http, or an https page loading http scripts; warns when you click the password box |
| D14 | Popup > Check a link or message: paste text, nothing is opened |
| D15 | Popup > I already entered something: checklist by what you gave, optional next-day reminder |
| D16 | Optional block list for session-replay and ad pixels (off by default) |
Behaviour seen on the page shows in the popup flag list. Only the kind and a count are kept, cleared when the tab navigates.
Permissions: contextMenus (right-click check), alarms (reminder), declarativeNetRequest (D16). **downloads** (D4) and **notifications** (D15 reminder) are optional: Decoy asks only when you switch them on in the popup. The all-sites access is needed for the automatic scan and cannot be avoided.

## Active guards, first batch (details)
Run inside every page (`src/guard.js`). They only block or delay; they never fill or submit. Every block shows a small chip with **Allow this once**.
- **Clipboard guard:** blocks a page copying `powershell`/`mshta`/`cmd /c`/`curl | sh` when you weren't clicking, or when the page says "press Win+R / Ctrl+V / I'm not a robot" (ClickFix). Docs "Copy" buttons are left alone. Silent crypto-address swaps are blocked.
- **Permission guard:** location/camera/mic/notifications/clipboard-read asked without a click are held back until you tap Allow. Three or more in 2 minutes counts as strong.
- **Scareware guard:** stops alert-box loops after 2, flags back-button trapping, offers **Close this tab**.
What fired shows up in the popup flag list. Only the kind and a count are kept, cleared when the tab navigates.

## Test lab (fake scam sites on your own machine)
```
npm run testbed      # then open http://localhost:8080
```
Load `dist/` in Chrome, open each link, use the popup. Nothing leaves your machine (`*.localhost` names).
| Page | Expect |
|---|---|
| paypal-secure-login, arnazon-signin | scan: Likely scam |
| nike-outlet-sale | scan: A bit off (weak signals only, capped) |
| honest-shop, quiet-shop | scan: Looks fine; dummy: No leak seen |
| grabber | scan: Looks fine; dummy: **data grabber** (keystrokes, password, bounce, OTP ask) |
| tracker-shop | dummy: No leak seen + info line (hashed email to ad pixel) |
Protection pages (`npm run e2e:protect`): paypal-secure-login, link-trick, clickjack, fake-window, checkout-skim, auto-download, pixel-shop. Guard pages: fake-captcha, clipboard-swap, permission-spam, virus-alert should be blocked; docs-install, store-locator, spa-app must be left alone (`npm run e2e:guard`).
The "collector" page shows what the pretend attacker received. `npm run e2e:testbed` runs all of this automatically.

## How it decides
| File | What |
|---|---|
| `src/scanner.js` | domain checks (brand + lure words, look-alikes, subdomain tricks, look-alike letters) and page checks (only on pages asking for a login/card) |
| `src/assess.js` | trust (top-40k, institutions, you), age, combo flags, 2-year dampening |
| `src/score.js` | sum with diminishing returns, then evidence caps (no strong flag <= 35, one strong <= 69, "Likely scam" needs 2 strong or a feed hit) |
| `src/watcher.js` | runs inside the page, wraps fetch/XHR/beacon/WebSocket/pixels/form submit, looks for the dummy values (plain, url, base64, hex, sha256/sha1/md5) |
| `src/destinations.js`, `src/verdict.js` | who got the data, how bad is that, one verdict |
| `src/background.js` | per-tab test state (session storage), input validation on watcher messages |

## False-positive guards
Top-40k allowlist, real domain parsing (Public Suffix List), common-word list, generic brand names, typo-only matches are weak, trusted institutions, "I trust this site", evidence caps. Measured: 0.025% of ~360k held-out real sites get a brand/look-alike flag.

## Privacy
Nothing leaves your browser. The domain-age lookup (rdap.org) is **off by default**: turn it on in the popup if you want it; it sends only the domain. The dummy test stores only destinations and field names, never typed values, and clears when you press Stop or close the browser.

## Known limits
Heuristics only (no live threat feed yet). Watcher can miss cross-origin iframes the page builds itself, and anything the server does later. Domain age needs network access to rdap.org.


## Download check (v0.7)

When a download finishes, Decoy looks at it and tells you in plain words: **Problem found**, **Be careful**, or **Nothing suspicious found**. It never says "clean" or "safe": it checks for tricks (a program wearing a .pdf name, `invoice.pdf.exe`, right-to-left name tricks, programs or macros hidden in zips and Office files, PDFs that launch things, unsigned installers from unfamiliar sites). It is not an antivirus.

- Harmless files (pictures, text) stay quiet. Risky kinds and problems get a pop-up on the tab you downloaded from, with a "Delete the file" button on problems.
- To look *inside* finished files, switch on "Allow access to file URLs" for Decoy in `chrome://extensions`. Without it, only the name and source are checked, and the pop-up says so.
- The popup has **Check a file**: pick any file and it is analysed locally with a SHA-256 shown. Nothing is uploaded.
- Switch it off with "Check finished downloads" in More protection. Needs the optional downloads permission (same toggle as the program-download pause).
- Try it: `node testbed/server.mjs`, then open the `download-lab` page. `npm run e2e:download` runs it automatically.


## Protect each other (optional, v0.8)
Needs your own Decoy cloud (see `backend/DEPLOY.md`; `node backend/dev-server.mjs` for a local test copy). Everything is off until you add the address.
- **Shared warnings:** sites that 3 or more different people's dummy tests caught grabbing data get a "confirmed by other Decoy users" flag. Never applied to sites you trust, the top-sites list, or government/education sites.
- **Help warn others:** when your dummy test catches a grabber, send the site address and the type of finding. Nothing you typed.
- **Trusted people:** up to 3. They must say yes by email first (or "No thanks", which blocks them for good). They get an email when you stay 30 seconds on a Likely-scam page, submit through the warning, or download a dangerous file. The email has the site, the time and whether you typed anything, never what you typed. Dummy tests never trigger alerts.
- Test: `npm run e2e:cloud`, `npm run test:backend`.

## Testing updates on your own machine (no store needed)
- One time: `git clone https://github.com/zenyinnaya-star/decoy.git`, `cd decoy`, `npm install`, `npm run build`, then at `chrome://extensions` turn on Developer mode and "Load unpacked" the `dist` folder.
- Every update: `git pull && npm run build`, then press the reload arrow on the Decoy card.
- Hands-free: `npm run dev` rebuilds on every change and the extension reloads itself within a couple of seconds. (`npm run update` = pull, install, dev.) Test builds only.
