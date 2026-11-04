function rng(seedStr) {
  let h = 1779033703 ^ seedStr.length;
  for (let i = 0; i < seedStr.length; i++) {
    h = Math.imul(h ^ seedStr.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return () => {
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    return ((h ^= h >>> 16) >>> 0) / 4294967296;
  };
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
const digits = (r, n) => Array.from({ length: n }, () => Math.floor(r() * 10)).join("");

export function persona(host) {
  const r = rng(host);
  const first = pick(r, ["Alex", "Jordan", "Taylor", "Casey", "Riley", "Morgan", "Jamie", "Quinn"]);
  const last = pick(r, ["Doe", "Smith", "Nguyen", "Okafor", "Martin", "Lee", "Brown", "Singh"]);
  const user = `${first}.${last}${digits(r, 3)}`.toLowerCase();
  return {
    first, last, full: `${first} ${last}`, user,
    email: `${user}@example.com`,
    phone: `403555${digits(r, 4)}`,
    street: `${100 + Math.floor(r() * 800)} Fake Street`,
    city: "Calgary", state: "AB", zip: "T2P 0A1", country: "Canada",
    password: `Dc!${digits(r, 6)}xQz`,
    dob: "1990-01-15",
    card: "4242424242424242", exp: "12/30", cvc: "123",
  };
}

function fieldKey(el) {
  const s = [el.type, el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute("aria-label"),
    el.labels?.[0]?.textContent].join(" ").toLowerCase();
  if (el.type === "password") return "password";
  if (el.type === "email" || /e-?mail/.test(s)) return "email";
  if (el.type === "tel" || /phone|mobile|tel\b/.test(s)) return "phone";
  if (/cc-number|card.?number|cardnum/.test(s)) return "card";
  if (/cc-exp|expir|mm.?\/?.?yy/.test(s)) return "exp";
  if (/cvv|cvc|csc|security.?code/.test(s)) return "cvc";
  if (/zip|postal/.test(s)) return "zip";
  if (/first.?name|given/.test(s)) return "first";
  if (/last.?name|family|surname/.test(s)) return "last";
  if (/user.?name|login|handle/.test(s)) return "user";
  if (/birth|dob|bday/.test(s)) return "dob";
  if (/street|address/.test(s)) return "street";
  if (/city|town/.test(s)) return "city";
  if (/state|province/.test(s)) return "state";
  if (/country/.test(s)) return "country";
  if (/name/.test(s)) return "full";
}

// override: a canary identity from the dummy test (its email/password/phone replace the stable ones).
export function fill(doc = document, host = location.hostname, override = null) {
  const p = override ? { ...persona(host), ...override } : persona(host);
  const setter = Object.getOwnPropertyDescriptor(doc.defaultView.HTMLInputElement.prototype, "value").set;
  let n = 0;
  doc.querySelectorAll("input, textarea").forEach((el) => {
    if (el.disabled || el.readOnly || ["hidden", "submit", "button", "checkbox", "radio", "file"].includes(el.type)) return;
    const k = fieldKey(el);
    if (!k || !p[k]) return;
    if (el.tagName === "INPUT") setter.call(el, p[k]); else el.value = p[k]; // React/Vue friendly
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    n++;
  });
  return { filled: n, persona: { name: p.full, email: p.email } };
}
