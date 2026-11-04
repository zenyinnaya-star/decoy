// D14: score a pasted link or message without opening anything. Pure; domain checks come from the caller.
const FILE_EXT = new Set("js css png jpg jpeg gif svg pdf txt html htm php json xml zip exe md ts py doc docx".split(" "));
const URL_RE = /\b(?:https?:\/\/[^\s<>"')]+|(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/[^\s<>"')]*)?)/gi;

export function extractUrls(text) {
  const out = [];
  for (const m of String(text || "").matchAll(URL_RE)) {
    let s = m[0].replace(/[.,;:!?]+$/, "");
    if (!/^https?:\/\//i.test(s)) {
      const tld = s.split("/")[0].split(".").pop().toLowerCase();
      if (FILE_EXT.has(tld) || /^\d+(\.\d+)+$/.test(s)) continue;
      s = "http://" + s; // no scheme given: judge the address only
      out.push({ url: s, bare: true });
    } else out.push({ url: s, bare: false });
    if (out.length >= 10) break;
  }
  return out;
}

const T = (id, label, weight, tier = "weak") => ({ id, label, weight, tier });
export function textFlags(text) {
  const t = String(text || "").toLowerCase();
  const flags = [];
  const scare = [
    /your account (has been|will be|is) (suspended|locked|limited|closed|disabled)/, /verify your (account|identity|information|details)/,
    /unusual (sign-?in|login|activity)/, /confirm your (billing|payment) (details|information)/,
    /congratulations.{0,60}(won|winner|selected)/, /(package|parcel|delivery).{0,70}(unpaid|fee|redeliver|reschedule|on hold|could not be delivered)/,
  ].filter((r) => r.test(t)).length;
  if (scare >= 2) flags.push(T("scare", "Scare or prize wording (several patterns)", 30, "strong"));
  else if (scare === 1) flags.push(T("scare", "Scare or prize wording", 12));
  if (/(send|share|reply with|tell us|read out|give (me|us)).{0,20}(password|otp|code|pin|sin\b|ssn|card number)/.test(t))
    flags.push(T("askcode", "Asks you to hand over a code, password or number", 35, "strong"));
  if (/(arrest|warrant|legal action|lawsuit|frozen).{0,70}(cra|irs|tax|police|rcmp|bank|account)/.test(t))
    flags.push(T("authority", "Threatens legal trouble from an agency or bank", 30, "strong"));
  if (/(gift cards?|bitcoin|crypto|western union|moneygram|wire transfer|e-?transfer)/.test(t) && /(pay|send|buy|transfer)/.test(t))
    flags.push(T("paymethod", "Asks for hard-to-refund payment", 18));
  if (/(within|in) (24|48|12) hours|act now|final notice|immediately|last chance/.test(t)) flags.push(T("urgent", "Pressure to act fast", 8));
  if (/call (us |this number |now |immediately)/.test(t) && /\+?\d[\d\s().-]{8,}/.test(t)) flags.push(T("callback", "Pushes you to call a number", 10));
  return flags;
}
