// D11: links whose visible text says one site but go to another.
import { parseHost } from "./scanner.js";

export const SHORTENERS = new Set(`bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at rb.gy
  tiny.cc t.ly s.id v.gd lnkd.in bl.ink soo.gd qr.ae adf.ly`.split(/\s+/));

const TEXT_URL = /^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:[/:?#]\S*)?$/i;
const NOT_TLD = new Set("js css png jpg jpeg gif svg pdf txt html htm php json xml zip exe md ts py".split(" "));

// Email/ad tracking redirects. A "Visit example.com" link going through click.mailer.net is normal on a newsletter page.
const TRACK_LABEL = new Set("click clicks links link email e em mail go track trk tracking redirect r t url mkt news".split(" "));
const TRACK_DOMAIN = new Set("sendgrid.net mandrillapp.com list-manage.com mailchimp.com hubspotlinks.com t.co google.com bing.com facebook.com l.facebook.com".split(" "));

// -> null | { shown, actual }  (registrable domains)
// opts.sensitive: the page asks for a login/card. Tracking-redirect leniency is OFF there (scammers use it too).
export function linkMismatch(text, href, pageHost, opts = {}) {
  const t = String(text || "").trim();
  if (t.length > 80 || /\s/.test(t)) return null; // sentences are not "a URL shown as text"
  const m = TEXT_URL.exec(t);
  if (!m || NOT_TLD.has(m[1].split(".").pop().toLowerCase())) return null;
  let u; try { u = new URL(href, `https://${pageHost}/`); } catch { return null; }
  if (!/^https?:$/.test(u.protocol)) return null;
  const shown = parseHost(m[1].toLowerCase()).domain;
  const actual = parseHost(u.hostname.toLowerCase()).domain;
  if (!shown || !actual || shown === actual) return null;
  try { if (decodeURIComponent(u.href).toLowerCase().includes(shown)) return null; } catch {} // target carried in the URL: normal redirect
  if (!opts.sensitive && (TRACK_DOMAIN.has(actual) || TRACK_LABEL.has(u.hostname.split(".")[0]))) return null;
  return { shown, actual };
}

export const isShortener = (host) => SHORTENERS.has(String(host).toLowerCase().replace(/^www\./, ""));
