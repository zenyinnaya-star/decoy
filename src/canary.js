import { md5 } from "./md5.js";

export const TEST_CARD = "4242424242424242";

const FIRST = ["Alex", "Jordan", "Taylor", "Casey", "Riley", "Morgan", "Jamie", "Quinn"];
const LAST = ["Doe", "Smith", "Nguyen", "Okafor", "Martin", "Lee", "Brown", "Singh"];

function rand(n) {
  const a = crypto.getRandomValues(new Uint32Array(n));
  return [...a];
}
const token = (len) => rand(len).map((x) => "abcdefghjkmnpqrstuvwxyz23456789"[x % 31]).join("");
const digits = (len) => rand(len).map((x) => x % 10).join("");

// A one-off identity. The email, password and phone carry random tokens so we can
// recognise them in outgoing traffic. The card is the public 4242 test number.
export function makeCanary() {
  const first = FIRST[rand(1)[0] % FIRST.length];
  const last = LAST[rand(1)[0] % LAST.length];
  const t = token(7);
  return {
    first, last, full: `${first} ${last}`,
    user: `dc${t}`,
    email: `dc-${t}@example.com`,
    password: `Dc-${token(8)}-${digits(3)}!`,
    phone: `403555${digits(4)}`,
    card: TEST_CARD,
  };
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const utf8 = (s) => new TextEncoder().encode(s);
const b64 = (s) => { try { return btoa(String.fromCharCode(...utf8(s))); } catch { return null; } };

async function digest(alg, s) {
  try { return hex(new Uint8Array(await crypto.subtle.digest(alg, utf8(s)))); } catch { return null; } // http pages have no subtle
}

// Every shape the dummy values might take on the wire.
export async function buildNeedles(id) {
  const out = [];
  const add = (kind, enc, text) => { if (text && text.length >= 8) out.push({ kind, enc, text: CASEFREE.has(enc) ? text.toLowerCase() : text }); };
  const CASEFREE = new Set(["hex", "sha256", "sha1", "md5"]);

  for (const [kind, v] of [["email", id.email], ["password", id.password], ["phone", id.phone]]) {
    add(kind, "plain", v);
    add(kind, "url", encodeURIComponent(v));
    add(kind, "base64", b64(v));
    add(kind, "hex", hex(utf8(v)));
  }
  // Ad pixels send hashed emails (trimmed + lowercased first).
  const em = id.email.trim().toLowerCase();
  add("email", "sha256", await digest("SHA-256", em));
  add("email", "sha1", await digest("SHA-1", em));
  add("email", "md5", md5(em));

  add("card", "plain", id.card);
  add("card", "plain", id.card.replace(/(.{4})/g, "$1 ").trim());
  add("card", "plain", id.card.replace(/(.{4})/g, "$1-").slice(0, -1));

  const seen = new Set();
  return out.filter((n) => (seen.has(n.text) ? false : seen.add(n.text)));
}
