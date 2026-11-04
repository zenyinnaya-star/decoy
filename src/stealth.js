// Pages can print a function to see if it was replaced ("function fetch() { [native code] }").
// Make our wrappers print like the originals, so malicious pages can't easily tell they are being watched.
const originals = new WeakMap();
let patched = false;

export function disguise(wrapper, original) {
  try { originals.set(wrapper, original); } catch {}
  if (patched) return wrapper;
  patched = true;
  const ts = Function.prototype.toString;
  const fake = function toString() { return ts.call(originals.get(this) || this); };
  originals.set(fake, ts);
  try { Function.prototype.toString = fake; } catch {}
  return wrapper;
}

// Take a snapshot of property descriptors BEFORE patching, then call disguiseAll(snap) after.
// targets are thunks so a missing API (e.g. no Clipboard) can't throw.
export function snapshot(targets) {
  return targets.map((t) => { try { const [o, p] = t(); return [o, p, Object.getOwnPropertyDescriptor(o, p)]; } catch { return null; } }).filter((x) => x && x[2]);
}
export function disguiseAll(snap) {
  for (const [o, p, before] of snap) {
    try {
      const now = Object.getOwnPropertyDescriptor(o, p);
      if (!now) continue;
      if (typeof now.value === "function" && typeof before.value === "function" && now.value !== before.value) disguise(now.value, before.value);
      if (now.get && before.get && now.get !== before.get) disguise(now.get, before.get);
      if (now.set && before.set && now.set !== before.set) disguise(now.set, before.set);
    } catch {}
  }
}
