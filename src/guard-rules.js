// Pure rules for the active guards (no DOM). Tested in test/guard.test.js.

// Commands scam pages ask you to paste into Run / Terminal ("ClickFix").
const CMD = [
  /\bpowershell(\.exe)?\b[^\n]*(\s-e(nc|ncodedcommand)?\s|\s-w(indowstyle)?\s+h|\biex\b|invoke-expression|downloadstring|\b(irm|iwr)\b|invoke-(webrequest|restmethod))/i,
  /\bmshta(\.exe)?\b/i,
  /\bcmd(\.exe)?\s*\/[ck]\b/i,
  /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i,
  /\bbase64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh\b/i,
  /\bcertutil\b[^\n]*-urlcache/i,
  /\bbitsadmin\b[^\n]*\/transfer/i,
  /\bmsiexec\b[^\n]*\/i\s*https?:/i,
  /\brundll32\b[^\n]*(http|\.dll)/i,
];
const CRYPTO = [/\bbc1[a-z0-9]{25,59}\b/, /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/, /\b0x[a-fA-F0-9]{40}\b/, /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/];

// Wording that tells you to paste something yourself.
export const LURE = /(win(dows)?\s*(key\s*)?\+\s*r\b|windows\s+key|run\s+dialog|press\s+(ctrl|control|cmd|⌘)\s*\+?\s*v|ctrl\s*\+\s*v|verify\s+(that\s+)?you\s*(are|'re)\s+(not\s+a\s+robot|human)|i'?m\s+not\s+a\s+robot)/i;

// ctx: { gesture: boolean (real click/tap just happened), lure: () => boolean (lazy page-text check) }
// -> null (fine) | { kind, label }
export function clipboardRisk(text, ctx) {
  const t = String(text ?? "").slice(0, 4000);
  if (!t.trim()) return null;
  if (CMD.some((r) => r.test(t))) {
    // A docs page's "Copy" button (real click, no "paste this into Run" wording) is normal.
    if (!ctx.gesture || ctx.lure()) return { kind: "clipboard-command", label: "Page tried to copy a command for you to run" };
    return null;
  }
  // Silent address swap: copy buttons have a click, hijackers don't.
  if (!ctx.gesture && CRYPTO.some((r) => r.test(t))) return { kind: "clipboard-crypto", label: "Page copied a crypto address without you clicking" };
  return null;
}

// n events inside windowMs.
export class Burst {
  constructor(windowMs) { this.w = windowMs; this.t = []; }
  hit(now = Date.now()) { this.t.push(now); while (this.t.length && now - this.t[0] > this.w) this.t.shift(); return this.t.length; }
}

// Guard flags now live in the shared table (flags.js). Re-exported so older imports keep working.
export { GUARD_KINDS } from "./flags.js";
