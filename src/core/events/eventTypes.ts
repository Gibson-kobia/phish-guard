/**
 * PhishGuard Behavioral Security Event Types
 * 
 * Defines the strongly typed structural event model for real-time
 * browser security observation, correlation, and timeline synthesis.
 * 
 * STRICT PRIVACY MANDATE:
 * This layer exclusively captures structural security metadata.
 * It NEVER captures, transmits, or stores passwords, form input values,
 * credit card numbers, CVVs, 2FA tokens, cookies, keystrokes, or raw page body text.
 */

export type ThreatSeverity = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityVerdict = 'SAFE' | 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'DANGEROUS';

export type SecurityEventType =
  | 'NAVIGATION_COMMITTED'
  | 'PAGE_LOADED'
  | 'BRAND_IDENTITY_DETECTED'
  | 'DOMAIN_MISMATCH_DETECTED'
  | 'FREE_HOSTING_DETECTED'
  | 'CREDENTIAL_FORM_DETECTED'
  | 'PAYMENT_FORM_DETECTED'
  | 'VERIFICATION_CODE_FORM_DETECTED'
  | 'INSECURE_FORM_DETECTED'
  | 'CROSS_ORIGIN_FORM_ACTION'
  | 'NETWORK_REQUEST_OBSERVED'
  | 'CROSS_ORIGIN_REQUEST_OBSERVED'
  | 'CREDENTIAL_SUBMISSION_PATTERN'
  | 'REDIRECT_HOP_OBSERVED'
  | 'DOWNLOAD_TRIGGERED'
  | 'SCAREWARE_CUE_DETECTED'
  | 'TYPOSQUAT_DETECTED'
  | 'HOMOGLYPH_DETECTED'
  | 'RISK_ESCALATED';

export interface BaseSecurityEvent {
  id: string;
  timestamp: number;
  tabId: number;
  frameId?: number;
  documentId?: string;
  pageUrl: string;
  pageOrigin: string;
  type: SecurityEventType;
  severity: ThreatSeverity;
  title: string;
  description: string;
  evidence?: Record<string, unknown>;
  destinationHostname?: string;
  isSameOrigin?: boolean;
  isCrossOrigin?: boolean;
}

export interface NetworkSecurityEvent extends BaseSecurityEvent {
  type: 'NETWORK_REQUEST_OBSERVED' | 'CROSS_ORIGIN_REQUEST_OBSERVED' | 'CREDENTIAL_SUBMISSION_PATTERN';
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | string;
  destinationUrl: string;
  destinationHostname: string;
  requestType: 'xmlhttprequest' | 'fetch' | 'sub_frame' | 'main_frame' | 'script' | 'ping' | 'other' | string;
  isCrossOrigin: boolean;
  isSuspiciousDestination?: boolean;
  timeSinceCredentialInputMs?: number;
  sensitiveSubmissionPattern?: boolean;
}

export interface PageBrandingEvent extends BaseSecurityEvent {
  type: 'BRAND_IDENTITY_DETECTED' | 'DOMAIN_MISMATCH_DETECTED' | 'FREE_HOSTING_DETECTED';
  claimedBrandName: string;
  canonicalDomains: string[];
  currentHostname: string;
  currentRegisteredDomain: string;
  isFreeHostingProvider: boolean;
  freeHostingProviderName?: string;
  isOfficialDomain: boolean;
  brandTokensFound: string[];
  pageTitle?: string;
}

export interface FormSecurityEvent extends BaseSecurityEvent {
  type: 
    | 'CREDENTIAL_FORM_DETECTED'
    | 'PAYMENT_FORM_DETECTED'
    | 'VERIFICATION_CODE_FORM_DETECTED'
    | 'INSECURE_FORM_DETECTED'
    | 'CROSS_ORIGIN_FORM_ACTION';
  formType: 'LOGIN' | 'PAYMENT' | 'VERIFICATION_2FA' | 'REGISTRATION' | 'SEARCH' | 'GENERIC';
  actionUrl: string;
  actionHostname: string;
  actionIsCrossOrigin: boolean;
  actionIsInsecure: boolean;
  hasPasswordField: boolean;
  hasCreditCardField: boolean;
  has2FAField: boolean;
  inputCount: number;
  hiddenFieldCount: number;
}

export interface NavigationSecurityEvent extends BaseSecurityEvent {
  type: 'NAVIGATION_COMMITTED' | 'REDIRECT_HOP_OBSERVED';
  navigationType?: 'link' | 'typed' | 'form_submit' | 'reload' | 'auto_subframe' | 'other';
  initialUrl?: string;
  redirectHopCount?: number;
  hasUrlShortener?: boolean;
  hopDomains?: string[];
}

export interface DownloadSecurityEvent extends BaseSecurityEvent {
  type: 'DOWNLOAD_TRIGGERED';
  downloadId: number;
  filename: string;
  fileExtension: string;
  downloadUrl: string;
  isExecutable: boolean;
  originRiskScore: number;
}

export interface CorrelatedEvidence {
  id: string;
  type: string;
  severity: ThreatSeverity;
  weight: number;
  title: string;
  explanation: string;
  evidenceMetadata?: Record<string, unknown>;
}

export interface CorrelatedThreatAssessment {
  tabId: number;
  url: string;
  domain: string;
  timestamp: number;
  score: number; // 0 to 100
  severity: ThreatSeverity;
  verdict: SecurityVerdict;
  evidence: CorrelatedEvidence[];
  signals?: CorrelatedEvidence[];
  reasons: string[];
  claimedBrand?: {
    name: string;
    canonicalDomains: string[];
    isImpersonated: boolean;
  };
  eventsCount: number;
  timeline: BaseSecurityEvent[];
}
