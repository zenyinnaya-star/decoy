import test from "node:test";
import assert from "node:assert/strict";
import { analyze, sniff, extOf } from "../src/filecheck.js";

const enc = (s) => new TextEncoder().encode(s);
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const le16 = (n) => new Uint8Array([n & 255, (n >> 8) & 255]);
const le32 = (n) => new Uint8Array([n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255]);

// minimal zip (stored, crc ignored) with optional "password" flag
function zip(names, { encrypted = false } = {}) {
  const locals = [], cds = []; let off = 0;
  for (const nm of names) {
    const n = enc(nm), fl = encrypted ? 1 : 0;
    const lh = cat(le32(0x04034b50), le16(20), le16(fl), le16(0), le16(0), le16(0), le32(0), le32(0), le32(0), le16(n.length), le16(0), n);
    cds.push(cat(le32(0x02014b50), le16(20), le16(20), le16(fl), le16(0), le16(0), le16(0), le32(0), le32(0), le32(0), le16(n.length), le16(0), le16(0), le16(0), le16(0), le32(0), le32(off), n));
    locals.push(lh); off += lh.length;
  }
  const cd = cat(...cds);
  return cat(...locals, cd, le32(0x06054b50), le16(0), le16(0), le16(names.length), le16(names.length), le32(cd.length), le32(off), le16(0));
}
// minimal PE with/without a signature block
function pe(signed) {
  const b = new Uint8Array(1024); b[0] = 0x4d; b[1] = 0x5a; b[0x3c] = 0x80;
  b.set([0x50, 0x45, 0, 0], 0x80);
  b[0x80 + 24] = 0x0b; b[0x80 + 25] = 0x02; // PE32+
  if (signed) b[0x80 + 24 + 112 + 32 + 4] = 0x40; // security directory size
  return b;
}
const ole2 = (extra = "") => cat(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), enc(" ".repeat(64) + extra));
const src = (o = {}) => ({ host: "files.example.net", trusted: false, flagged: false, ...o });
const sev = (r) => r.reasons.map((x) => x.sev + ":" + x.text).join(" | ");

test("sniff recognises common file types by their first bytes", () => {
  assert.equal(sniff(pe(false)), "pe");
  assert.equal(sniff(enc("%PDF-1.7\n")), "pdf");
  assert.equal(sniff(zip(["a.txt"])), "zip");
  assert.equal(sniff(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0])), "png");
  assert.equal(sniff(enc("@echo off\r\ndel *.*")), "script");
  assert.equal(sniff(enc("Just some notes about lunch")), "text");
});

test("a program dressed up as a document is a PROBLEM", () => {
  const r = analyze({ name: "invoice.pdf", head: pe(true), size: 1024, source: src() });
  assert.equal(r.verdict, "problem"); assert.match(sev(r), /Named \.pdf, but the contents are a Windows program/);
});

test("double extensions and hidden direction tricks are PROBLEMS, even without opening the file", () => {
  assert.equal(analyze({ name: "invoice.pdf.exe", head: null, source: src() }).verdict, "problem");
  assert.equal(analyze({ name: "photo.jpg.scr", head: null }).verdict, "problem");
  assert.equal(analyze({ name: "report‮fdp.exe", head: null }).verdict, "problem");
  assert.equal(analyze({ name: "setup" + " ".repeat(8) + ".exe", head: null }).verdict, "problem");
});

test("an ordinary unsigned installer from an unfamiliar site is only BE CAREFUL; a signed one is lower-key", () => {
  const a = analyze({ name: "tool-setup.exe", head: pe(false), size: 1024, source: src() });
  assert.equal(a.verdict, "careful");
  const b = analyze({ name: "tool-setup.exe", head: pe(true), size: 1024, source: src() });
  assert.equal(b.verdict, "nothing"); assert.match(sev(b), /publisher signature/);
  const c = analyze({ name: "tool-setup.exe", head: pe(false), size: 1024, source: src({ trusted: true }) });
  assert.equal(c.verdict, "nothing");
});

test("a program from a site Decoy rates as risky is a PROBLEM", () => {
  assert.equal(analyze({ name: "update.exe", head: pe(true), size: 1024, source: src({ flagged: true, host: "paypa1-secure.xyz" }) }).verdict, "problem");
  assert.equal(analyze({ name: "notes.txt", head: enc("hello there"), size: 11, source: src({ flagged: true }) }).verdict, "nothing"); // harmless kind: no scare
});

test("zip archives: programs inside, disguised programs inside, password protection", () => {
  assert.equal(analyze({ name: "photos.zip", head: zip(["a.jpg", "b.jpg"]), size: 400 }).verdict, "nothing");
  assert.equal(analyze({ name: "bundle.zip", head: zip(["readme.txt", "setup.exe"]), size: 400 }).verdict, "careful");
  assert.equal(analyze({ name: "photos.zip", head: zip(["invoice.pdf.exe"]), size: 400 }).verdict, "problem");
  const locked = analyze({ name: "docs.zip", head: zip(["a.txt"], { encrypted: true }), size: 400 });
  assert.equal(locked.verdict, "careful"); assert.match(sev(locked), /password-protected/);
});

test("Office files: macros are flagged; a .docx that has macros is a disguise", () => {
  assert.equal(analyze({ name: "letter.docx", head: zip(["[Content_Types].xml", "word/document.xml"]), size: 500 }).verdict, "nothing");
  assert.equal(analyze({ name: "letter.docx", head: zip(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"]), size: 500 }).verdict, "problem");
  assert.equal(analyze({ name: "budget.xlsm", head: zip(["[Content_Types].xml", "xl/workbook.xml", "xl/vbaProject.bin"]), size: 500 }).verdict, "careful");
  assert.equal(analyze({ name: "old.doc", head: ole2("_VBA_PROJECT_CUR"), size: 200 }).verdict, "careful");
  assert.equal(analyze({ name: "old.doc", head: ole2(), size: 200 }).verdict, "nothing");
});

test("PDF: launch action is a problem, auto-run script is careful, plain PDF is fine", () => {
  assert.equal(analyze({ name: "a.pdf", head: enc("%PDF-1.4\n1 0 obj<</Type/Catalog/OpenAction<</S/Launch/F(cmd.exe)>>>>"), size: 100 }).verdict, "problem");
  assert.equal(analyze({ name: "a.pdf", head: enc("%PDF-1.4\n<</OpenAction<</S/JavaScript/JS(app.alert(1))>>>>"), size: 100 }).verdict, "careful");
  assert.equal(analyze({ name: "a.pdf", head: enc("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF"), size: 60 }).verdict, "nothing");
});

test("scripts, shortcuts and disk images are BE CAREFUL; plain files stay quiet", () => {
  assert.equal(analyze({ name: "fix.bat", head: enc("@echo off\r\ndel x"), size: 20 }).verdict, "careful");
  assert.equal(analyze({ name: "doc.lnk", head: null }).verdict, "careful");
  assert.equal(analyze({ name: "game.iso", head: null }).verdict, "careful");
  assert.equal(analyze({ name: "photo.png", head: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]), size: 8 }).verdict, "nothing");
  assert.equal(analyze({ name: "notes.txt", head: enc("buy milk"), size: 8 }).verdict, "nothing");
});

test("without file access the check is flagged as limited and still catches name tricks", () => {
  const r = analyze({ name: "setup.exe", head: null, source: src() });
  assert.equal(r.limited, true); assert.equal(r.verdict, "careful");
  assert.equal(extOf("Archive.TAR.GZ  "), "gz");
});
