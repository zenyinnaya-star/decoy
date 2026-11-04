// Brands that phishing commonly impersonates. Only lowercase, no TLD.
export const BRANDS = [
  "google", "gmail", "youtube", "paypal", "amazon", "apple", "icloud", "microsoft", "outlook",
  "office365", "facebook", "instagram", "whatsapp", "messenger", "netflix", "linkedin", "twitter",
  "github", "dropbox", "ebay", "walmart", "costco", "bestbuy", "target", "shopify", "stripe",
  "bankofamerica", "wellsfargo", "chase", "citibank", "capitalone", "americanexpress", "amex",
  "rbc", "td", "scotiabank", "bmo", "cibc", "tangerine", "desjardins", "interac", "hsbc", "barclays",
  "canadapost", "fedex", "ups", "dhl", "usps", "purolator", "coinbase", "binance", "kraken",
  "metamask", "ledger", "trezor", "steam", "steamcommunity", "discord", "spotify", "adobe",
  "docusign", "yahoo", "airbnb", "booking", "uber", "roblox", "epicgames", "playstation", "xbox",
  "telegram", "tiktok", "snapchat", "venmo", "cashapp", "zelle", "wise", "revolut",
  "cra", "irs", "servicecanada", "costco", "rogers", "bell", "telus", "verizon", "att", "tmobile",
];

// Words phishers bolt onto a brand: paypal-secure-login, apple-id-verify, etc.
export const LURE_WORDS = new Set([
  "login", "signin", "logon", "secure", "security", "verify", "verification", "account", "accounts",
  "update", "support", "help", "helpdesk", "service", "services", "auth", "id", "wallet", "billing",
  "payment", "pay", "confirm", "recovery", "recover", "unlock", "unlocked", "restore", "official",
  "online", "bank", "banking", "refund", "claim", "reward", "rewards", "gift", "bonus", "alert",
  "notice", "customer", "care", "team", "portal", "web", "app", "access",
  "validate", "validation", "check", "delivery", "fee", "fees", "redeliver", "redelivery", "reschedule", "shipment", "tax", "taxes", "parcel", "tracking", "track", "invoice", "airdrop",
]);

// Payment / auth providers legit sites post forms to.
export const FORM_TARGET_OK = new Set([
  "stripe.com", "paypal.com", "braintreegateway.com", "squareup.com", "shopify.com", "adyen.com",
  "google.com", "apple.com", "microsoftonline.com", "live.com", "auth0.com", "okta.com",
  "mailchimp.com", "list-manage.com", "hubspot.com", "hsforms.com", "formspree.io", "typeform.com",
  "klaviyo.com", "salesforce.com", "pardot.com", "marketo.com", "convertkit.com", "netlify.com",
]);

// Brand names that are also everyday words. Too noisy to match in an address
// ("secure-hotel-booking.com"), but still checked against the page title.
export const GENERIC_BRANDS = new Set([
  "booking", "target", "wise", "bell", "ledger", "kraken", "chase",
  "td", "att", "ups", "cra", "irs", "bmo", "rbc", "dhl",
]);

// Real brands, but one letter off a common word (cloud, mobile). Skip typo matching only.
export const NO_TYPO = new Set(["icloud", "tmobile", "apple", "steam", "uber", "xbox", "amex"]);
