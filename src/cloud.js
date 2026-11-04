// Client for the Decoy cloud (Cloudflare Worker). Everything here is opt-in and does nothing until you set an address.
// Stored in chrome.storage.local:
//   cloudUrl      address of your deployed worker
//   useShared     fetch the shared warning list
//   shareReports  send confirmed grabber sites (domain + finding type only) to the shared list
//   cloud         { id, key }  this install's login (random, made by the server)
//   cloudList     [domain, ...] cached shared list
//   guardians     number of active trusted people (cached so alerts can be skipped cheaply)
const get = (k) => chrome.storage.local.get(k);

export const baseUrl = async () => String((await get("cloudUrl")).cloudUrl || "").replace(/\/+$/, "");

async function raw(base, method, path, { body, auth } = {}) {
  const headers = {};
  if (body) headers["content-type"] = "application/json";
  if (auth) headers.authorization = `Bearer ${auth.id}.${auth.key}`;
  const r = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: "omit", referrerPolicy: "no-referrer" });
  let data = null; try { data = await r.json(); } catch {}
  if (!r.ok) throw Object.assign(new Error(data?.error || `Request failed (${r.status})`), { status: r.status });
  return data;
}

async function install(base) {
  const { cloud } = await get("cloud");
  if (cloud?.id && cloud?.key && cloud.base === base) return cloud;
  const made = await raw(base, "POST", "/v1/install");
  const c = { id: made.id, key: made.key, base };
  await chrome.storage.local.set({ cloud: c });
  return c;
}

// Signed-in call. One retry with a fresh install if the server forgot us (e.g. a reset database).
export async function api(method, path, body) {
  const base = await baseUrl();
  if (!base) throw new Error("Decoy cloud isn't set up");
  let me = await install(base);
  try { return await raw(base, method, path, { body, auth: me }); }
  catch (e) {
    if (e.status !== 401) throw e;
    await chrome.storage.local.remove("cloud");
    me = await install(base);
    return raw(base, method, path, { body, auth: me });
  }
}

export async function ping() { const base = await baseUrl(); if (!base) throw new Error("Add your Decoy cloud address first"); return raw(base, "GET", "/"); }

// ---- shared warning list ----
export async function syncList() {
  const { useShared } = await get("useShared");
  const base = await baseUrl();
  if (!useShared || !base) return false;
  const j = await raw(base, "GET", "/v1/list");
  await chrome.storage.local.set({ cloudList: (j.domains || []).map((x) => x.d).slice(0, 5000), cloudListAt: Date.now() });
  return true;
}
export async function onSharedList(domain) {
  if (!domain) return false;
  const { useShared, cloudList = [] } = await get(["useShared", "cloudList"]);
  return !!useShared && cloudList.includes(domain);
}

// ---- reports: only sites where the dummy test caught real grabbing, only domain + finding type ----
export async function reportFindings(domain, findings) {
  const { shareReports } = await get("shareReports");
  if (!shareReports || !(await baseUrl())) return 0;
  let n = 0;
  for (const finding of new Set(findings)) { try { await api("POST", "/v1/reports", { domain, finding }); n++; } catch {} }
  return n;
}

// Turn the dummy test's strong findings into the few finding types the server accepts.
export function findingTypes(items) {
  const out = new Set();
  for (const i of items) {
    if (i.severity !== "strong") continue;
    if (i.kind === "redirect") out.add("brand-redirect");
    else if (i.kind === "grabber") out.add("grabber-endpoint");
    else if (i.beforeSubmit) out.add("keystroke-leak");
    else if (i.kinds?.some((k) => k === "password" || k === "card") && ["unknown", "suspicious", "analytics", "formsvc"].includes(i.kind)) out.add("password-third-party");
  }
  return [...out];
}

// ---- trusted people ----
export async function guardians() {
  const j = await api("GET", "/v1/guardians");
  await chrome.storage.local.set({ guardianCount: j.guardians.filter((g) => g.status === "active").length });
  return j.guardians;
}
export const invite = (email, name, yourName) => api("POST", "/v1/guardians", { email, name, yourName });
export const removeGuardian = (id) => api("DELETE", `/v1/guardians/${id}`);

// kind: likely | grabber | download | entered. Skipped quietly when nobody is listening.
export async function alertGuardians(kind, domain, entered = false) {
  const { guardianCount = 0 } = await get("guardianCount");
  if (!guardianCount || !(await baseUrl())) return false;
  try { await api("POST", "/v1/alerts", { kind, domain, entered }); return true; } catch { return false; }
}
