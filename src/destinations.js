import { parseHost } from "./scanner.js";
import { isLoopback } from "./trust.js";

const set = (s) => new Set(s.split(/\s+/).filter(Boolean));

// Payment + sign-in providers real sites legitimately hand credentials to.
const PROVIDERS = set(`stripe.com stripe.network paypal.com paypalobjects.com braintreegateway.com braintree-api.com
  squareup.com square.com adyen.com checkout.com authorize.net klarna.com afterpay.com shopify.com shopifycs.com
  google.com gstatic.com recaptcha.net hcaptcha.com apple.com microsoftonline.com microsoft.com live.com
  auth0.com okta.com oktapreview.com cloudflare.com arkoselabs.com`);

// Ad / analytics services. They get hashed emails all the time on normal sites.
const ANALYTICS = set(`facebook.com facebook.net doubleclick.net google-analytics.com googletagmanager.com
  googleadservices.com tiktok.com snapchat.com sc-static.net linkedin.com licdn.com pinterest.com twitter.com x.com
  ads-twitter.com hotjar.com hotjar.io clarity.ms segment.io segment.com mixpanel.com amplitude.com fullstory.com
  heap.io heapanalytics.com criteo.com taboola.com outbrain.com bing.com sentry.io datadoghq.com newrelic.com
  nr-data.net intercom.io klaviyo.com`);

// Form-handling / email services.
const FORMSVC = set(`formspree.io formsubmit.co getform.io mailchimp.com list-manage.com hsforms.com hsforms.net
  hubspot.com typeform.com jotform.com wufoo.com convertkit.com sendgrid.net sendinblue.com brevo.com`);

// Places stolen data is dumped: paste sites, request catchers, tunnels, chat webhooks.
const GRABBER = set(`pastebin.com hastebin.com ghostbin.com paste.ee webhook.site requestbin.com requestbin.net
  pipedream.net ngrok.io ngrok-free.app ngrok.app trycloudflare.com localtunnel.me loca.lt serveo.net interact.sh
  oast.fun oast.live oast.pro oast.site oast.online oast.me burpcollaborator.net hooks.slack.com`);

// Free hosts that scam kits love, but real small apps use too.
const SUSPICIOUS = set(`workers.dev firebaseio.com glitch.me repl.co 000webhostapp.com infinityfreeapp.com byethost.com`);

// True if the host, or any parent of it, is in the set (api.stripe.com -> stripe.com; x.ngrok-free.app -> ngrok-free.app).
function inSet(set, host) {
  const parts = host.split(".");
  for (let i = 0; i < parts.length - 1; i++) if (set.has(parts.slice(i).join("."))) return true;
  return false;
}

// kind: first | provider | analytics | formsvc | grabber | suspicious | unknown
export function classify(urlStr, pageHost) {
  let u;
  try { u = new URL(urlStr, `https://${pageHost}/`); } catch { return { kind: "unknown", host: String(urlStr).slice(0, 60) }; }
  const host = u.hostname.toLowerCase();
  const here = parseHost(String(pageHost).toLowerCase());
  const there = parseHost(host);
  const domain = there.domain || host;
  const insecure = u.protocol === "http:" && !isLoopback(host);

  if (host === String(pageHost).toLowerCase() || (here.domain && domain === here.domain))
    return { kind: "first", host, domain, insecure };

  if (there.isIp) return { kind: "grabber", host, domain, insecure, note: "a raw IP address" };
  if (host === "api.telegram.org" && /^\/bot/i.test(u.pathname)) return { kind: "grabber", host, domain, insecure, note: "a Telegram bot" };
  if (/(^|\.)(discord|discordapp)\.com$/.test(host) && /\/api\/webhooks\//i.test(u.pathname))
    return { kind: "grabber", host, domain, insecure, note: "a Discord webhook" };
  if (inSet(GRABBER, host)) return { kind: "grabber", host, domain, insecure, note: "a data-catching service" };
  if (host === "docs.google.com" && u.pathname.startsWith("/forms")) return { kind: "formsvc", host, domain, insecure, note: "Google Forms" };
  if (host === "script.google.com" && u.pathname.startsWith("/macros")) return { kind: "formsvc", host, domain, insecure, note: "a Google Apps Script" };
  if (inSet(PROVIDERS, host)) return { kind: "provider", host, domain, insecure };
  if (inSet(ANALYTICS, host)) return { kind: "analytics", host, domain, insecure };
  if (inSet(FORMSVC, host)) return { kind: "formsvc", host, domain, insecure };
  if (inSet(SUSPICIOUS, host)) return { kind: "suspicious", host, domain, insecure };
  return { kind: "unknown", host, domain, insecure };
}
