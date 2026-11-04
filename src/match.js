// Find canary values inside a chunk of text (URL + request body).
// needle = { kind: "email"|"password"|"phone"|"card", enc: "plain"|"url"|"base64"|"hex"|"sha256"|"sha1"|"md5", text }
// Pure and tiny: shared by the page watcher and the background.
const CASE_FREE = new Set(["hex", "sha256", "sha1", "md5"]);

export function matchNeedles(hay, needles) {
  if (!hay || !needles?.length) return [];
  const variants = [hay];
  try { variants.push(decodeURIComponent(hay.replace(/\+/g, " "))); } catch {}
  const lower = variants.map((v) => v.toLowerCase());
  const out = [];
  for (const n of needles) {
    const found = CASE_FREE.has(n.enc)
      ? lower.some((v) => v.includes(n.text))
      : variants.some((v) => v.includes(n.text));
    if (found) out.push({ kind: n.kind, enc: n.enc });
  }
  return out;
}
