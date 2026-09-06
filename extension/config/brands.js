const DEFAULT_PROTECTED_BRANDS = [
  {
    id: "vinted",
    name: "Vinted",
    canonicalDomains: [
      "vinted.com",
      "vinted.fr",
      "vinted.de",
      "vinted.co.uk",
      "vinted.es",
      "vinted.it",
      "vinted.pl",
      "vinted.lt",
      "vinted.cz",
      "vinted.nl",
      "vinted.be",
      "vinted.at",
      "vinted.se"
    ],
    keywords: ["vinted", "vintedmarket", "vinted-market", "secondhand", "vinted-verify"],
    category: "ECOMMERCE"
  },
  {
    id: "paypal",
    name: "PayPal",
    canonicalDomains: ["paypal.com", "paypal-objects.com", "paypal.me", "paypal-community.com"],
    keywords: ["paypal", "paypaii", "paypai", "paypal-verify", "paypal-security"],
    category: "FINANCIAL"
  },
  {
    id: "stripe",
    name: "Stripe",
    canonicalDomains: ["stripe.com", "checkout.stripe.com", "stripe.network"],
    keywords: ["stripe", "stripe-checkout", "stripe-auth"],
    category: "FINANCIAL"
  },
  {
    id: "steam",
    name: "Steam / Valve",
    canonicalDomains: ["steampowered.com", "steamcommunity.com", "valvesoftware.com"],
    keywords: ["steam", "steamcommunity", "steam-login", "steamguard"],
    category: "TECH"
  },
  {
    id: "docusign",
    name: "DocuSign",
    canonicalDomains: ["docusign.com", "docusign.net"],
    keywords: ["docusign", "docusign-sign", "docusign-envelope"],
    category: "PRODUCTIVITY"
  },
  {
    id: "dhl",
    name: "DHL Express",
    canonicalDomains: ["dhl.com", "dhl.de", "dhl.co.uk"],
    keywords: ["dhl", "dhl-tracking", "dhl-delivery"],
    category: "OTHER"
  },
  {
    id: "google",
    name: "Google / Gmail",
    canonicalDomains: ["google.com", "google.co.uk", "google.ca", "gmail.com", "accounts.google.com", "gstatic.com", "googleusercontent.com"],
    keywords: ["google", "gmail", "g00gle", "goog1e", "google-verify", "google-security"],
    category: "TECH"
  },
  {
    id: "microsoft",
    name: "Microsoft / Outlook / Office",
    canonicalDomains: ["microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com", "msn.com", "sharepoint.com"],
    keywords: ["microsoft", "outlook", "office365", "micros0ft", "ms-online", "office-update"],
    category: "TECH"
  },
  {
    id: "apple",
    name: "Apple / iCloud",
    canonicalDomains: ["apple.com", "icloud.com", "appleid.apple.com", "itunes.com"],
    keywords: ["apple", "icloud", "appl-id", "apple-id", "apple-support", "icloud-find"],
    category: "TECH"
  },
  {
    id: "amazon",
    name: "Amazon",
    canonicalDomains: ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com", "media-amazon.com"],
    keywords: ["amazon", "amaz0n", "amazon-order", "amazon-security", "aws-login"],
    category: "ECOMMERCE"
  },
  {
    id: "netflix",
    name: "Netflix",
    canonicalDomains: ["netflix.com", "nflxvideo.net"],
    keywords: ["netflix", "netf1ix", "netflix-verify", "netflix-billing"],
    category: "TECH"
  },
  {
    id: "chase",
    name: "Chase Bank",
    canonicalDomains: ["chase.com", "jpmorganchase.com"],
    keywords: ["chase", "chase-online", "chase-security", "chase-verify"],
    category: "FINANCIAL"
  },
  {
    id: "wellsfargo",
    name: "Wells Fargo",
    canonicalDomains: ["wellsfargo.com"],
    keywords: ["wellsfargo", "wells-fargo", "wf-online", "wellsfargo-verify"],
    category: "FINANCIAL"
  },
  {
    id: "bankofamerica",
    name: "Bank of America",
    canonicalDomains: ["bankofamerica.com", "bofa.com"],
    keywords: ["bankofamerica", "bofa", "bofa-security", "bankofamerica-login"],
    category: "FINANCIAL"
  },
  {
    id: "facebook",
    name: "Meta / Facebook / Instagram",
    canonicalDomains: ["facebook.com", "fb.com", "instagram.com", "meta.com", "messenger.com"],
    keywords: ["facebook", "instagram", "faceb00k", "fb-verify", "meta-auth"],
    category: "SOCIAL"
  },
  {
    id: "binance",
    name: "Binance",
    canonicalDomains: ["binance.com", "binance.us", "bnbstatic.com"],
    keywords: ["binance", "binance-auth", "binance-verify", "binance-wallet"],
    category: "CRYPTO"
  },
  {
    id: "coinbase",
    name: "Coinbase",
    canonicalDomains: ["coinbase.com", "pro.coinbase.com"],
    keywords: ["coinbase", "c0inbase", "coinbase-login", "coinbase-verify"],
    category: "CRYPTO"
  },
  {
    id: "github",
    name: "GitHub",
    canonicalDomains: ["github.com", "github.io", "githubusercontent.com", "github.blog"],
    keywords: ["github", "g1thub", "github-login", "github-auth"],
    category: "TECH"
  },
  {
    id: "dropbox",
    name: "Dropbox",
    canonicalDomains: ["dropbox.com", "dropboxstatic.com"],
    keywords: ["dropbox", "dr0pbox", "dropbox-verify", "dropbox-share"],
    category: "TECH"
  }
];
const DEFAULT_ALLOWLIST = [
  "google.com",
  "accounts.google.com",
  "mail.google.com",
  "microsoft.com",
  "login.microsoftonline.com",
  "apple.com",
  "appleid.apple.com",
  "amazon.com",
  "paypal.com",
  "github.com",
  "cloudflare.com",
  "wikipedia.org",
  "mozilla.org",
  "developer.chrome.com",
  "nytimes.com",
  "bbc.com",
  "cnn.com",
  "stackexchange.com",
  "stackoverflow.com"
];
const DEMO_KNOWN_MALICIOUS_DOMAINS = [
  "paypal-security-verification-login.com",
  "secure-apple-id-verify.online",
  "accounts-google-auth-login.xyz",
  "chase-online-banking-alert.click",
  "netflix-payment-failed-update.top",
  "binance-wallet-synchronize.cfd",
  "microsoft-365-passcode-reset.vip"
];
const KNOWN_URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "buff.ly",
  "ow.ly",
  "cutt.ly",
  "rebrand.ly",
  "shorte.st",
  "tiny.cc",
  "bc.vc"
];
export {
  DEFAULT_ALLOWLIST,
  DEFAULT_PROTECTED_BRANDS,
  DEMO_KNOWN_MALICIOUS_DOMAINS,
  KNOWN_URL_SHORTENERS
};
