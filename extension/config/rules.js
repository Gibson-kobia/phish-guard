import { DEFAULT_PROTECTED_BRANDS, DEFAULT_ALLOWLIST, DEMO_KNOWN_MALICIOUS_DOMAINS } from './brands.js';
const SUSPICIOUS_KEYWORDS = [
  "login",
  "signin",
  "sign-in",
  "log-in",
  "verify",
  "verification",
  "verif",
  "security",
  "secure",
  "account",
  "acc-update",
  "update-account",
  "manage-account",
  "recover",
  "recovery",
  "unlock",
  "unusual-activity",
  "billing",
  "payment",
  "invoice",
  "credit-card",
  "wallet",
  "seed-phrase",
  "private-key",
  "auth",
  "authenticate",
  "2fa",
  "session",
  "confirm",
  "suspend",
  "suspended",
  "re-login",
  "password-reset",
  "passcode",
  "webscr",
  "cmd=_login-run",
  "portal",
  "client-area",
  "customer-service",
  "support-ticket"
];
const HIGH_RISK_TLDS = [
  "xyz",
  "top",
  "click",
  "link",
  "work",
  "gq",
  "cf",
  "ml",
  "ga",
  "tk",
  "surf",
  "icu",
  "cam",
  "buzz",
  "rest",
  "fit",
  "monster",
  "vip",
  "quest",
  "sbs",
  "cfd",
  "live",
  "online",
  "site",
  "pw"
];
const HOMOGLYPH_MAP = {
  "\u0430": "a",
  // Cyrillic small letter a
  "\u0441": "c",
  // Cyrillic small letter es
  "\u0435": "e",
  // Cyrillic small letter ie
  "\u043E": "o",
  // Cyrillic small letter o
  "\u0440": "p",
  // Cyrillic small letter er
  "\u0455": "s",
  // Cyrillic small letter dze
  "\u0501": "d",
  // Cyrillic small letter komi de
  "\u051B": "q",
  // Cyrillic small letter san
  "\u0456": "i",
  // Ukrainian-Byelorussian i
  "\u0458": "j",
  // Cyrillic small letter je
  "\u0443": "y",
  // Cyrillic small letter u
  "\u0445": "x",
  // Cyrillic small letter ha
  "\u0475": "v",
  // Cyrillic small letter izhitsa
  "\u0461": "w",
  // Cyrillic small letter omega
  "0": "o",
  // digit 0 to letter o
  "1": "l",
  // digit 1 to letter l (paypa1 -> paypal)
  "v": "u",
  "vv": "w",
  "rn": "m",
  "cl": "d"
};
const SUSPICIOUS_PORTS = [
  "8080",
  "8443",
  "8000",
  "8888",
  "2082",
  "2083",
  "2086",
  "2087",
  "8880",
  "3000",
  "5000",
  "9000"
];
const COMPOUND_PENALTY_TYPOSQUAT_LOGIN = 30;
const COMPOUND_PENALTY_IP_LOGIN = 35;
const COMPOUND_PENALTY_CROSS_ORIGIN = 20;
const COMPOUND_PENALTY_SOCENG_LOGIN = 25;
const LEGITIMATE_BRAND_DAMPENER_FACTOR = 0.15;
const REDIRECT_CHAIN_TIMEOUT_MS = 15e3;
const DOM_MUTATION_THROTTLE_MS = 1500;
const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  detectionSensitivity: "BALANCED",
  warningThreshold: 70,
  blockThreshold: 90,
  enableUrlAnalysis: true,
  enableTyposquatting: true,
  enableDomAnalysis: true,
  enableSocialEngineering: true,
  enableRedirectAnalysis: true,
  enableDownloadContext: true,
  enableReputationLayer: true,
  enableNotifications: true,
  protectedBrands: DEFAULT_PROTECTED_BRANDS,
  allowlist: DEFAULT_ALLOWLIST,
  blocklist: DEMO_KNOWN_MALICIOUS_DOMAINS,
  developerMode: false,
  scanHistoryLimit: 100
};
const SENSITIVITY_MULTIPLIERS = {
  CONSERVATIVE: 0.85,
  BALANCED: 1,
  AGGRESSIVE: 1.25
};
export {
  COMPOUND_PENALTY_CROSS_ORIGIN,
  COMPOUND_PENALTY_IP_LOGIN,
  COMPOUND_PENALTY_SOCENG_LOGIN,
  COMPOUND_PENALTY_TYPOSQUAT_LOGIN,
  DEFAULT_SETTINGS,
  DOM_MUTATION_THROTTLE_MS,
  HIGH_RISK_TLDS,
  HOMOGLYPH_MAP,
  LEGITIMATE_BRAND_DAMPENER_FACTOR,
  REDIRECT_CHAIN_TIMEOUT_MS,
  SENSITIVITY_MULTIPLIERS,
  SUSPICIOUS_KEYWORDS,
  SUSPICIOUS_PORTS
};
