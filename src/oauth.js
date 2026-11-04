// D10: what is this "Sign in with ..." screen really asking for? Parsed from the URL, not the page.
const G = "https://www.googleapis.com/auth/";
const RULES = [
  // [pattern, plain English, broad?]
  [/^https:\/\/mail\.google\.com\/?$/, "Read, send and delete ALL your email", true],
  [/gmail\.(readonly|metadata)$/, "Read all your email", true],
  [/gmail\.(modify|compose|send|insert|settings)/, "Read or send email as you", true],
  [new RegExp(`^${G.replace(/\//g, "\\/")}drive$`), "See, edit and delete ALL your Google Drive files", true],
  [/drive\.(readonly|metadata)/, "See all your Google Drive files", true],
  [/drive\.(file|appdata)$/, "Only files this app creates in Drive", false],
  [/contacts/, "Your contacts", true],
  [/calendar(?!\.)|calendar\.(events|readonly)/, "Your calendar", true],
  [/^(openid|email|profile)$|userinfo\.(email|profile)/, "Your name and email address", false],
  // Microsoft
  [/^mail\.(readwrite|send)/i, "Read and send email as you", true],
  [/^mail\.read/i, "Read your email", true],
  [/^files\.(readwrite|read)\.all$/i, "Read your OneDrive files", true],
  [/^files\./i, "Your OneDrive files", true],
  [/^(contacts|calendars)\./i, "Your contacts / calendar", true],
  [/^directory\./i, "Your organisation's directory", true],
  [/^offline_access$/i, "Keep access after you leave (stays signed in)", true],
  [/^user\.read$/i, "Basic profile", false],
  // GitHub
  [/^(repo|public_repo)$/, "Full access to your code repositories", true],
  [/^(admin:|delete_repo|workflow|write:|site_admin)/, "Change or delete things in your GitHub account", true],
  [/^(read:user|user:email|user)$/, "Your GitHub profile / email", false],
];

export function detectProvider(u) {
  const h = u.hostname.toLowerCase();
  if (h === "accounts.google.com" && /^\/o\/oauth2\//.test(u.pathname)) return "Google";
  if ((h === "login.microsoftonline.com" || h === "login.live.com") && /oauth2/.test(u.pathname)) return "Microsoft";
  if (h === "github.com" && u.pathname === "/login/oauth/authorize") return "GitHub";
  return null;
}

// -> null | { provider, scopes:[{raw,plain,broad}], broad }
export function parseScopes(urlStr) {
  let u; try { u = new URL(urlStr); } catch { return null; }
  const provider = detectProvider(u);
  if (!provider) return null;
  const raw = (u.searchParams.get("scope") || "").split(/[\s,]+/).filter(Boolean);
  const scopes = raw.map((s) => {
    const r = RULES.find(([re]) => re.test(s)) || RULES.find(([re]) => re.test(s.replace(G, "")));
    return r ? { raw: s, plain: r[1], broad: r[2] } : { raw: s, plain: s.replace(G, ""), broad: false };
  });
  return { provider, scopes, broad: scopes.some((s) => s.broad) };
}
