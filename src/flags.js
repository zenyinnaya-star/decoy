// ONE table for every flag Decoy can raise. The score, the popup, the "why this score" panel,
// the report button and the privacy label all read from here. Pure data, no DOM, safe in any world.
//   src:    where it comes from: domain | page | guard | shell | list
//   tier:   strong | weak (see score.js caps)
//   weight: default points. Flags with a computed weight keep `weight` as the typical value; the emitter may override it.
//   label:  default one-line text. Emitters may add specifics ("Address imitates paypal").
//   why:    plain-English reason a person can read ("why this matters").
const F = (src, tier, weight, label, why) => ({ src, tier, weight, label, why });

export const FLAGS = {
  // ---- web address ----
  ip: F("domain", "strong", 40, "Address is a raw IP number", "Real companies use names, not number-only addresses. Scam kits often run from bare IPs."),
  punycode: F("domain", "weak", 30, "Address uses look-alike characters", "Letters from other alphabets can imitate a real brand's name."),
  tld: F("domain", "weak", 10, "Address ends in a TLD often used by throwaway sites", "Cheap endings are used a lot for short-lived scam sites. Plenty of honest sites use them too."),
  brandlure: F("domain", "strong", 40, "Address combines a brand with login/security words", "Names like brand-secure-login.com are how phishing pages dress up."),
  lookalike: F("domain", "strong", 40, "Address imitates a well-known brand", "A one-letter difference from a famous site is a classic trick."),
  subbrand: F("domain", "strong", 35, "A brand name sits in front of a different site's address", "paypal.example.com is example.com, not PayPal."),
  subs: F("domain", "weak", 8, "Address has many sub-domain parts", "Long chains hide the real site name."),
  hyphens: F("domain", "weak", 8, "Address has several hyphens", "Scam addresses are often stitched together with hyphens."),
  http: F("domain", "weak", 8, "Page is not encrypted (http)", "Anything you type can be read on the way. Real sites use https."),
  userinfo: F("domain", "strong", 30, "Address hides the real site behind a name@ trick", "In name@site, everything before the @ is ignored and only the site after it matters."),
  short: F("domain", "weak", 12, "Shortened link: the real destination is hidden", "Short links hide where you end up."),
  age: F("domain", "weak", 18, "Website address is brand new", "Most scam sites are days old. New does not mean bad on its own."),

  // ---- page content ----
  nolegal: F("page", "weak", 8, "No privacy or terms links", "Real shops and services almost always have them."),
  brandmismatch: F("page", "strong", 30, "Page says it is a brand but the address is not theirs", "The page text claims a famous name while the address belongs to someone else."),
  xform: F("page", "strong", 25, "Form sends your details to another site", "Your password or card goes somewhere other than the site you are on."),
  insecureform: F("page", "strong", 35, "Form sends your details without encryption", "Details typed here can be read in transit."),
  mixed: F("page", "weak", 10, "Secure page loads insecure content", "Part of the page can be tampered with in transit."),
  nocontact: F("page", "weak", 8, "Shop has no contact details", "Real shops tell you how to reach them."),
  norefund: F("page", "weak", 6, "Shop has no refund or returns policy", "Missing policies are common on fake shops."),
  threat: F("page", "strong", 20, "Scare or prize language typical of phishing", "Panic ('account locked') and prizes push people to act without thinking."),
  pressure: F("page", "weak", 8, "Countdown or 'act now' pressure", "Urgency is used to stop you from checking."),
  discount: F("page", "weak", 8, "Unusually big discounts", "Prices far below normal are the bait on fake shops."),
  payment: F("page", "weak", 8, "Unusual payment methods", "Gift cards, crypto or wire transfers are hard to reverse."),
  combo: F("page", "strong", 35, "Imitates a brand and asks for a login or card", "Brand imitation plus a sensitive form is the core phishing pattern."),
  newshop: F("page", "strong", 25, "Brand-new site with sale pressure and a payment form", "A new store, pushing urgency, wanting your card."),
  fakeshop: F("page", "strong", 30, "Shop looks fake: card form plus several shop warning signs", "Several small shop warnings stacked on a card form."),

  // ---- list ----
  feed: F("list", "strong", 80, "On a known scam list", "Matches a published phishing or malware list."),

  crowd: F("list", "strong", 70, "Other Decoy users confirmed this site grabs data", "Several different people tested this site with fake details and each saw the details sent somewhere they shouldn't go."),

  // ---- active guards (these fire from behaviour, not appearance) ----
  "clipboard-command": F("guard", "strong", 45, "Tried to copy a command for you to run (ClickFix)", "Fake 'verify you are human' pages get you to paste a command that installs malware."),
  "clipboard-crypto": F("guard", "strong", 40, "Copied a crypto address without a click", "Swapping a wallet address in your clipboard sends your money to the thief."),
  "perm-prompt": F("guard", "weak", 8, "Asked for a browser permission without a click", "Real sites ask when you press something that needs it."),
  "perm-repeat": F("guard", "strong", 35, "Kept asking for permissions without a click", "Repeated asks are a pressure tactic."),
  "scare-alert": F("guard", "strong", 40, "Popped repeated alert boxes", "Fake virus warnings flood you with alerts to scare you."),
  "scare-history": F("guard", "strong", 40, "Tried to trap the back button", "The page fills your history so you cannot leave."),
  clickjack: F("guard", "strong", 40, "Invisible layer over the page (click-jacking)", "A hidden layer makes you click something you cannot see."),
  bitb: F("guard", "strong", 45, "Fake browser window with a password box", "A drawn-on 'pop-up window' that imitates a real sign-in."),
  "skim-read": F("guard", "strong", 45, "A suspicious script read your card field", "A checkout skimmer steals card numbers as you type."),
  "skim-host": F("guard", "weak", 12, "Payment page loads an unfamiliar script", "Skimmers arrive as extra scripts on checkout pages."),
  replay: F("guard", "weak", 0, "Info: this page records your typing and mouse (session replay)", "Common analytics tool, but worth knowing on login or card pages."),
  "link-mismatch": F("guard", "weak", 8, "A link shows one address but goes to another", "What you see is not where you land."),
  "link-mismatch-login": F("guard", "strong", 30, "Login page has a link that shows one address but goes to another", "On a login page this is a strong phishing sign."),
  "oauth-broad": F("guard", "weak", 10, "App asks for broad access to your account", "Wide permissions can read or change a lot."),
  "oauth-broad-unverified": F("guard", "strong", 35, "Unverified app asks for broad access to your account", "An unknown app asking for wide access is how account takeovers start."),
  "download-flagged": F("guard", "strong", 40, "A file you downloaded looked dangerous", "The file was a program in disguise or had hidden tricks."),
  "download-exec": F("guard", "strong", 40, "Tried to download a program from an unfamiliar site", "Programs from unfamiliar sites are the main way malware arrives."),
};

export const IDS = Object.keys(FLAGS);
export const has = (id) => Object.hasOwn(FLAGS, id);
export const isStrong = (f) => f && f.tier === "strong";

// Flags raised by active guards, as [{id,tier,weight,label}] keyed by id. Kept for older imports.
export const GUARD_KINDS = Object.fromEntries(Object.entries(FLAGS).filter(([, v]) => v.src === "guard").map(([k, v]) => [k, { tier: v.tier, weight: v.weight, label: v.label }]));

// Make a ready-to-score flag from an id (+ optional overrides: label, weight, tier, extra fields).
export function make(id, over = {}) {
  const d = FLAGS[id];
  if (!d) return { id, tier: "weak", weight: 0, label: id, ...over };
  return { id, tier: d.tier, weight: d.weight, label: d.label, ...over };
}

// For the "Why this score" panel: every flag with its plain-English reason, strongest first.
export function explain(flags) {
  return [...flags]
    .map((f) => ({ id: f.id, tier: f.tier, weight: f.weight, label: f.label || FLAGS[f.id]?.label || f.id, why: FLAGS[f.id]?.why || "", src: FLAGS[f.id]?.src || "other" }))
    .sort((a, b) => (b.tier === "strong") - (a.tier === "strong") || b.weight - a.weight);
}
