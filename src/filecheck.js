// Download check. Pure: takes bytes + name + where it came from, returns a plain-English verdict.
// It looks for tricks and risky kinds of file. It can NEVER prove a file is safe, so the best answer is "nothing suspicious found".

const set = (s) => new Set(s.split(/\s+/).filter(Boolean));
export const PROGRAM_EXT = set("exe scr com pif dll cpl sys msi");
export const SCRIPT_EXT = set("bat cmd ps1 psm1 vbs vbe js jse wsf wsh hta reg jar");
export const EXEC_EXT = new Set([...PROGRAM_EXT, ...SCRIPT_EXT, ...set("lnk apk dmg pkg app appx msix msixbundle iso img vhd")]);
// What the user thinks they are getting
export const DISGUISE_EXT = set("pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif bmp mp3 mp4 csv odt");
const ARCHIVE_EXT = set("zip rar 7z gz tgz tar");
const OFFICE_MACRO_EXT = set("docm xlsm pptm xlam xlsb dotm");
const OFFICE_NEW = set("docx xlsx pptx");
const OFFICE_OLD = set("doc xls ppt");

const BIDI = /[‪-‮⁦-⁩]/;
const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const ascii = (b, from, to) => { let s = ""; for (let i = from; i < Math.min(to, b.length); i++) s += String.fromCharCode(b[i]); return s; };
const has = (b, needle) => { // fast-ish byte search
  const n = needle.length;
  outer: for (let i = 0; i <= b.length - n; i++) { for (let j = 0; j < n; j++) if (b[i + j] !== needle.charCodeAt(j)) continue outer; return true; }
  return false;
};

export function extOf(name) {
  const n = String(name || "").replace(/[\s.]+$/, "").toLowerCase();
  const i = n.lastIndexOf(".");
  return i >= 0 ? n.slice(i + 1) : "";
}

// What is this, really? Looks at the first bytes only.
export function sniff(b) {
  if (!b || b.length < 4) return "unknown";
  if (b[0] === 0x4d && b[1] === 0x5a) return "pe";
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "elf";
  const m = u32(b, 0);
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m)) return "macho";
  if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return "ole2";
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5)) return "zip";
  if (ascii(b, 0, 5) === "%PDF-") return "pdf";
  if (ascii(b, 0, 4) === "Rar!") return "rar";
  if (b[0] === 0x37 && b[1] === 0x7a && b[2] === 0xbc && b[3] === 0xaf) return "7z";
  if (b[0] === 0x1f && b[1] === 0x8b) return "gz";
  if (b[0] === 0x4c && b[1] === 0 && b[2] === 0 && b[3] === 0 && b[4] === 0x01 && b[5] === 0x14 && b[6] === 0x02) return "lnk";
  if (b[0] === 0x89 && ascii(b, 1, 4) === "PNG") return "png";
  if (b[0] === 0xff && b[1] === 0xd8) return "jpg";
  if (ascii(b, 0, 3) === "GIF") return "gif";
  if (b.length > 0x8006 && ascii(b, 0x8001, 0x8006) === "CD001") return "iso";
  const head = ascii(b, 0, 200).toLowerCase();
  if (/^(#!|@echo|powershell|<script|\s*<\?php)/.test(head) || /^\s*(function |\$|set-)/.test(head)) return "script";
  if (/^\s*<(!doctype html|html)/.test(head)) return "html";
  return "text";
}

// Does the executable carry a publisher signature block? (Presence only: we do not verify it.)
function peInfo(b) {
  try {
    const lfa = u32(b, 0x3c);
    if (lfa + 160 > b.length || u32(b, lfa) !== 0x4550) return { signed: null };
    const opt = lfa + 24, magic = u16(b, opt);
    const dd = opt + (magic === 0x20b ? 112 : 96) + 4 * 8; // security directory entry
    return { signed: dd + 8 <= b.length ? u32(b, dd + 4) > 0 : null, dll: (u16(b, lfa + 22) & 0x2000) !== 0 };
  } catch { return { signed: null }; }
}

// File names inside a zip (and whether any entry is password-protected).
function zipInfo(head, tail, size) {
  const names = []; let encrypted = false;
  const buf = size <= head.length || !tail ? head : tail;
  const base = buf === head ? 0 : size - tail.length;
  let e = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (u32(buf, i) === 0x06054b50) { e = i; break; }
  let ok = false;
  if (e >= 0) {
    const count = u16(buf, e + 10), cdOff = u32(buf, e + 16) - base;
    if (cdOff >= 0 && cdOff < buf.length) {
      let p = cdOff; ok = true;
      for (let k = 0; k < count && k < 5000 && p + 46 <= buf.length && u32(buf, p) === 0x02014b50; k++) {
        const fl = u16(buf, p + 8), nl = u16(buf, p + 28), xl = u16(buf, p + 30), cl = u16(buf, p + 32);
        if (fl & 1) encrypted = true;
        names.push(ascii(buf, p + 46, p + 46 + nl));
        p += 46 + nl + xl + cl;
      }
    }
  }
  if (!ok) { // big file: walk local headers at the start
    let p = 0;
    for (let k = 0; k < 2000 && p + 30 <= head.length && u32(head, p) === 0x04034b50; k++) {
      const fl = u16(head, p + 6), cs = u32(head, p + 18), nl = u16(head, p + 26), xl = u16(head, p + 28);
      if (fl & 1) encrypted = true;
      names.push(ascii(head, p + 30, p + 30 + nl));
      if (fl & 8 || !cs) break;
      p += 30 + nl + xl + cs;
    }
  }
  return { names, encrypted };
}

const LABEL = { pe: "a Windows program", elf: "a program", macho: "a Mac program", lnk: "a shortcut that can run commands", script: "a script", html: "a web page", ole2: "an old Office file", zip: "a zip archive", pdf: "a PDF" };

/**
 * analyze({ name, head, tail, size, source })
 *   head: first bytes (or null if we could not read the file: name/source checks only)
 *   source: { host, trusted, flagged } or null (unknown, e.g. dropped into the popup)
 * -> { verdict: "problem" | "careful" | "nothing", reasons: [{sev, text}], kind, limited }
 */
export function analyze({ name, head = null, tail = null, size = 0, source = null }) {
  const reasons = [];
  const add = (sev, text) => { if (!reasons.some((r) => r.text === text)) reasons.push({ sev, text }); };
  const n = String(name || "file");
  const ext = extOf(n);
  const parts = n.replace(/[\s.]+$/, "").toLowerCase().split(".");
  const prev = parts.length > 2 ? parts[parts.length - 2] : "";
  const fromSite = source?.host ? ` from ${source.host}` : "";

  // ---- the name ----
  if (BIDI.test(n)) add("problem", "The name uses a hidden text-direction trick to fake the file type.");
  if (EXEC_EXT.has(ext) && DISGUISE_EXT.has(prev)) add("problem", `Named like a ${prev.toUpperCase()} file but it is really a .${ext} ${PROGRAM_EXT.has(ext) ? "program" : "file that runs code"}.`);
  if (/\s{4,}\.[a-z0-9]+$/i.test(n)) add("problem", "The name is padded with spaces to hide the real file type.");
  if (/[. ]+$/.test(n)) add("careful", "The name ends with dots or spaces, which Windows ignores. Used to hide file types.");

  // ---- what it really is ----
  const limited = !head;
  let kind = "unknown";
  if (head) {
    kind = sniff(head);
    if (DISGUISE_EXT.has(ext) && ["pe", "elf", "macho", "lnk", "script"].includes(kind))
      add("problem", `Named .${ext}, but the contents are ${LABEL[kind]}. It is not what it claims to be.`);

    if (kind === "pe") {
      const p = peInfo(head);
      if (EXEC_EXT.has(ext) || !DISGUISE_EXT.has(ext)) {
        if (p.signed === false && !source?.trusted) add("careful", `A program${fromSite} with no publisher signature. Only run it if you went looking for it.`);
        else if (p.signed === false) add("info", "This program has no publisher signature.");
        else if (p.signed) add("info", "This program has a publisher signature (Decoy did not verify it).");
        else add("careful", `A program${fromSite}. Only run it if you went looking for it.`);
      }
    }
    if (kind === "script" || SCRIPT_EXT.has(ext)) add("careful", "Scripts can do anything on your computer. Only open it if you wrote it or know exactly what it does.");
    if (kind === "lnk" || ext === "lnk") add("careful", "Shortcut files can run hidden commands and are rarely a normal download.");
    if (kind === "iso" || ext === "iso" || ext === "img" || ext === "vhd") add("careful", "Disk images are often used to slip programs past scanners.");

    if (kind === "pdf") {
      if (has(head, "/Launch")) add("problem", "This PDF can launch another program when opened.");
      else {
        if ((has(head, "/JavaScript") || has(head, "/JS")) && (has(head, "/OpenAction") || has(head, "/AA"))) add("careful", "This PDF runs code as soon as it opens.");
        if (has(head, "/EmbeddedFile")) add("careful", "This PDF has another file hidden inside it.");
      }
    }
    if (kind === "ole2" && (OFFICE_OLD.has(ext) || ext === "")) {
      if (has(head, "_VBA_PROJECT") || has(head, "VBA") || has(head, "Macros")) add("careful", "This old-style Office file contains macros (code). Don't click 'Enable content' unless you trust the sender.");
    }
    if (kind === "zip") {
      const z = zipInfo(head, tail, size || head.length);
      const macro = z.names.some((x) => /vbaProject\.bin$/i.test(x));
      if (OFFICE_NEW.has(ext) && macro) add("problem", `Named .${ext}, which cannot contain macros, but it has macro code inside. That is a disguise.`);
      else if (OFFICE_MACRO_EXT.has(ext) || (z.names.some((x) => /^(word|xl|ppt)\//.test(x)) && macro)) add("careful", "This Office file contains macros (code). Don't click 'Enable content' unless you trust the sender.");
      const inner = z.names.filter((x) => EXEC_EXT.has(extOf(x)));
      const innerDouble = z.names.find((x) => EXEC_EXT.has(extOf(x)) && DISGUISE_EXT.has(x.replace(/[\s.]+$/, "").toLowerCase().split(".").slice(-2, -1)[0] || ""));
      if (innerDouble) add("problem", `Inside the archive: "${innerDouble}" is a program dressed up as a document.`);
      else if (inner.length && !macro) add("careful", `The archive contains ${inner.length === 1 ? "a program or script" : inner.length + " programs or scripts"} (${inner.slice(0, 2).join(", ")}${inner.length > 2 ? ", …" : ""}).`);
      if (z.encrypted) add("careful", "This archive is password-protected, so no scanner can look inside. Scammers use this on purpose.");
    }
    if ((kind === "rar" || kind === "7z") && ARCHIVE_EXT.has(ext)) add("info", "Decoy cannot look inside this kind of archive.");
  } else {
    // We could not open the file: judge the name and kind of file only.
    if (PROGRAM_EXT.has(ext)) add("careful", `A program${fromSite}. Only run it if you went looking for it.`);
    if (ext === "iso" || ext === "img") add("careful", "Disk images are often used to slip programs past scanners.");
    if (SCRIPT_EXT.has(ext)) add("careful", "Scripts can do anything on your computer. Only open it if you wrote it or know exactly what it does.");
    if (ext === "lnk") add("careful", "Shortcut files can run hidden commands and are rarely a normal download.");
    if (OFFICE_MACRO_EXT.has(ext)) add("careful", "Macro-enabled Office files contain code. Don't click 'Enable content' unless you trust the sender.");
  }

  // ---- where it came from ----
  const risky = ["pe", "script", "lnk", "iso", "zip", "ole2", "pdf", "elf", "macho"].includes(kind) || EXEC_EXT.has(ext) || ARCHIVE_EXT.has(ext) || OFFICE_MACRO_EXT.has(ext);
  if (source?.flagged && risky) add("problem", `It came from ${source.host}, a site Decoy rates as risky.`);

  let verdict = reasons.some((r) => r.sev === "problem") ? "problem" : reasons.some((r) => r.sev === "careful") ? "careful" : "nothing";
  return { verdict, reasons, kind, limited, risky };
}

export async function sha256hex(bytes) {
  const d = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
