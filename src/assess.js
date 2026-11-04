import { FORM_TARGET_OK } from "./brands.js";
import { parseHost } from "./scanner.js";
import { isInstitution } from "./trust.js";

// Flags that still matter on a trusted site.
const KEEP_WHEN_TRUSTED = new Set(["http"]);
const ESTABLISHED_DAYS = 730; // 2 years: weak signals count half
const NEW_DAYS = 365;

// Combine the page scan with things only the background knows (allowlist, domain age).
export function assess(scan, { isTrusted = () => false, isUserTrusted = () => false, ageDays = null } = {}) {
  let trustKind = null; // "you" | "institution" | "popular"
  if (scan.domain) {
    if (isUserTrusted(scan.domain)) trustKind = "you";
    else if (isInstitution(parseHost(scan.domain).suffix)) trustKind = "institution";
    else if (isTrusted(scan.domain)) trustKind = "popular";
  }
  const trusted = !!trustKind;

  let flags = scan.flags.filter((f) => {
    if (trusted && !KEEP_WHEN_TRUSTED.has(f.id)) return false;
    if (f.id === "xform" && (FORM_TARGET_OK.has(f.target) || isTrusted(f.target))) return false;
    return true;
  });

  if (!trusted) {
    const has = (id) => flags.some((f) => f.id === id);

    // A new domain only matters a lot when the site is also hiding the basics.
    const basicsOk = scan.sensitive && !has("nolegal") && !has("nocontact") && !has("norefund");
    const a = ageFlag(ageDays, scan.sensitive);
    if (a) {
      if (basicsOk) a.weight = Math.round(a.weight / 2);
      flags.push(a);
    }

    // Imitating a brand is far more serious when the page also wants a login or card.
    const brandy = flags.find((f) => f.brand && f.id !== "brandmismatch");
    if (brandy && scan.sensitive)
      flags.push({ id: "combo", label: `Imitates "${brandy.brand}" and asks for a login or card`, weight: 35, tier: "strong" });

    // Fake-shop pattern: brand-new site + payment form + (hard-to-refund payment / huge discounts / pressure).
    const isNew = ageDays != null && ageDays < NEW_DAYS;
    if (isNew && scan.sensitive && ["payment", "discount", "pressure"].filter(has).length >= 2)
      flags.push({ id: "newshop", label: "Brand-new site with sale pressure and a payment form", weight: 25, tier: "strong" });

    // D12: fake-shop check. Needs a card form plus three separate warning signs.
    const young = ageDays != null && ageDays < 90;
    const shopSigns = [has("payment"), has("norefund"), has("nocontact"), has("discount"), has("pressure"), young].filter(Boolean).length;
    if (scan.card && shopSigns >= 3)
      flags.push({ id: "fakeshop", label: "Shop looks fake: card form plus several shop warning signs", weight: 30, tier: "strong" });

    // Long-established domains: weak reputation signals count half.
    // (An unencrypted login is about the connection, not the site's reputation, so it keeps full weight.)
    if (ageDays != null && ageDays >= ESTABLISHED_DAYS)
      flags = flags.map((f) => (f.tier === "strong" || f.id === "http" ? f : { ...f, weight: Math.round(f.weight / 2) }));
  }
  return { ...scan, trusted, trustKind, flags };
}

export function ageFlag(days, sensitive = false) {
  if (days == null) return null;
  // New domain + asking for a login/card is the classic phishing combo.
  if (days < 30) return { id: "age", tier: "weak", label: `Website address was registered ${days} day(s) ago`, weight: sensitive ? 30 : 18 };
  if (days < 180) return { id: "age", tier: "weak", label: `Website address is only ${days} days old`, weight: sensitive ? 15 : 8 };
  return null;
}
