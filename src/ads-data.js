// Ad blocker data. Starter list: well-known ad networks and pop-up/push-ad networks. Third-party requests only,
// so a site's own pages and images are never touched. Add domains here; the build turns them into dist/ads.json.
export const AD_DOMAINS = `
doubleclick.net googlesyndication.com googleadservices.com adservice.google.com 2mdn.net pagead2.googlesyndication.com
adnxs.com adsrvr.org advertising.com criteo.com criteo.net taboola.com outbrain.com rubiconproject.com pubmatic.com
openx.net casalemedia.com indexww.com smartadserver.com adform.net amazon-adsystem.com media.net moatads.com
yieldmo.com sharethrough.com teads.tv triplelift.com 33across.com bidswitch.net contextweb.com lijit.com sovrn.com
mgid.com revcontent.com zemanta.com adroll.com adition.com gumgum.com kargo.com nativo.com undertone.com
spotxchange.com spotx.tv springserve.com freewheel.tv innovid.com tremorhub.com serving-sys.com flashtalking.com
adsafeprotected.com doubleverify.com ads-twitter.com adsymptotic.com adtechus.com adtech.de yahoo-ads.com
ads.yahoo.com advertising.yahoo.com gemini.yahoo.com bidtheatre.com improvedigital.com sonobi.com conversantmedia.com
emxdgt.com onetag-sys.com richaudience.com adkernel.com admixer.net adscale.de smilewanted.com appnexus.com
rhythmone.com lkqd.net lkqd.com video.unrulymedia.com unrulymedia.com seedtag.com sublime.xyz adyoulike.com
tapad.com bluekai.com rlcdn.com demdex.net mathtag.com turn.com adgrx.com 360yield.com ad.gt
popads.net popcash.net propellerads.com exoclick.com exosrv.com trafficjunky.com juicyads.com adsterra.com
hilltopads.net clickadu.com onclickads.net ad-maven.com admaven.com a-ads.com bidvertiser.com revenuehits.com
adcash.com richpush.co pushwoosh.com trafficstars.com trafficfactory.biz plugrush.com adxpansion.com
clickaine.com adspyglass.com tsyndicate.com ero-advertising.com hprofits.com mondiad.com evadav.com
monetag.com profitableratecpm.com highperformanceformat.com effectivegatecpm.com
`.split(/\s+/).filter(Boolean);

// Hide leftover empty ad slots. Deliberately specific: no generic ".ad" or "[class*=ad]" that could hide real content.
export const AD_CSS = [
  "ins.adsbygoogle", ".adsbygoogle", "[id^='google_ads_iframe']", "[id^='google_ads_']", "[id^='div-gpt-ad']",
  "iframe[src*='doubleclick.net']", "iframe[src*='googlesyndication.com']", "iframe[src*='adservice.google']",
  "iframe[src*='amazon-adsystem.com']", "iframe[src*='adnxs.com']", "iframe[src*='criteo.']",
  "[id^='taboola-']", ".trc_rbox_container", "[id^='outbrain']", ".OUTBRAIN", "[data-ad-slot]", "[data-google-query-id]",
].join(",") + "{display:none !important}";

export function adRules() {
  const types = ["script", "sub_frame", "image", "xmlhttprequest", "ping", "media", "stylesheet", "other"];
  return [{ id: 1, priority: 1, action: { type: "block" }, condition: { requestDomains: [...new Set(AD_DOMAINS)], domainType: "thirdParty", resourceTypes: types } }];
}
