import { ExtensionSettings } from '../types';
import { DEFAULT_PROTECTED_BRANDS, DEFAULT_ALLOWLIST, DEMO_KNOWN_MALICIOUS_DOMAINS } from './brands';

export const SUSPICIOUS_KEYWORDS: string[] = [
  'login', 'signin', 'sign-in', 'log-in',
  'verify', 'verification', 'verif', 'security', 'secure',
  'account', 'acc-update', 'update-account', 'manage-account',
  'recover', 'recovery', 'unlock', 'unusual-activity',
  'billing', 'payment', 'invoice', 'credit-card', 'wallet',
  'seed-phrase', 'private-key', 'auth', 'authenticate', '2fa',
  'session', 'confirm', 'suspend', 'suspended', 're-login',
  'password-reset', 'passcode', 'webscr', 'cmd=_login-run',
  'portal', 'client-area', 'customer-service', 'support-ticket'
];

export const HIGH_RISK_TLDS: string[] = [
  'xyz', 'top', 'click', 'link', 'work', 'gq', 'cf', 'ml', 'ga', 'tk',
  'surf', 'icu', 'cam', 'buzz', 'rest', 'fit', 'monster', 'vip', 'quest',
  'sbs', 'cfd', 'live', 'online', 'site', 'pw'
];

/**
 * Homoglyph visual substitution map
 * Normalizes visual lookalikes to Latin base characters.
 */
export const HOMOGLYPH_MAP: Record<string, string> = {
  'а': 'a', // Cyrillic small letter a
  'с': 'c', // Cyrillic small letter es
  'е': 'e', // Cyrillic small letter ie
  'о': 'o', // Cyrillic small letter o
  'р': 'p', // Cyrillic small letter er
  'ѕ': 's', // Cyrillic small letter dze
  'ԁ': 'd', // Cyrillic small letter komi de
  'ԛ': 'q', // Cyrillic small letter san
  'і': 'i', // Ukrainian-Byelorussian i
  'ј': 'j', // Cyrillic small letter je
  'у': 'y', // Cyrillic small letter u
  'х': 'x', // Cyrillic small letter ha
  'ѵ': 'v', // Cyrillic small letter izhitsa
  'ѡ': 'w', // Cyrillic small letter omega
  '0': 'o', // digit 0 to letter o
  '1': 'l', // digit 1 to letter l (paypa1 -> paypal)
  'v': 'u',
  'vv': 'w',
  'rn': 'm',
  'cl': 'd'
};

export const SUSPICIOUS_PORTS: string[] = [
  '8080', '8443', '8000', '8888', '2082', '2083', '2086', '2087', '8880', '3000', '5000', '9000'
];

// Heuristic engine penalty and dampening constants
export const COMPOUND_PENALTY_TYPOSQUAT_LOGIN = 30;
export const COMPOUND_PENALTY_IP_LOGIN = 35;
export const COMPOUND_PENALTY_CROSS_ORIGIN = 20;
export const COMPOUND_PENALTY_SOCENG_LOGIN = 25;
export const LEGITIMATE_BRAND_DAMPENER_FACTOR = 0.15;
export const REDIRECT_CHAIN_TIMEOUT_MS = 15000;
export const DOM_MUTATION_THROTTLE_MS = 1500;

export const DEFAULT_SETTINGS: ExtensionSettings = {
  protectionEnabled: true,
  detectionSensitivity: 'BALANCED',
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

export const SENSITIVITY_MULTIPLIERS = {
  CONSERVATIVE: 0.85,
  BALANCED: 1.0,
  AGGRESSIVE: 1.25
};
