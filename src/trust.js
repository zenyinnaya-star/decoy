// Government, education and military sites. Page checks are skipped on these.
const INST = new Set(["gov", "edu", "mil", "gouv", "govt"]);

export function isInstitution(suffix = "") {
  const parts = suffix.toLowerCase().split(".").filter(Boolean);
  if (parts.some((p) => INST.has(p))) return true; // .gov  .edu  .gov.uk  .edu.au
  if (parts.length >= 2 && parts.slice(0, -1).includes("ac")) return true; // .ac.uk  .ac.jp (not the bare .ac TLD)
  return suffix.toLowerCase() === "gc.ca"; // Government of Canada
}

// Traffic to your own machine never crosses a network, so "plain http" is not a risk there.
export function isLoopback(host = "") {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}
