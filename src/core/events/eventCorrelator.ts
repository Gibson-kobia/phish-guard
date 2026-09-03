/**
 * PhishGuard Multi-Signal Behavioral Security Event Correlator
 * 
 * Correlates observed structural events (Branding + Domain Hierarchy + Forms + Network Exfiltration + Redirects)
 * into a single explainable, compound-calibrated threat assessment.
 * 
 * Compound Rules:
 * - Brand Impersonation on Free Hosting + Active Credential Form + Verification Code + Cross-Origin POST = CRITICAL (85-98)
 * - Brand Domain Mismatch + Login Form = HIGH_RISK / DANGEROUS (75-92)
 * - E-Commerce / Payment Collection on Free Hosting without verified domain = SUSPICIOUS / HIGH_RISK (50-65)
 * - Raw IP / Insecure HTTP + Credential Form = CRITICAL (85-95)
 * - Known Brand Domain + Same-Origin Login Form + Legitimate Auth Request = SAFE (0-10)
 * - Legitimate Federated OAuth (Google/Apple/Microsoft) or Stripe Checkout = SAFE (0-10)
 * - Standard Static Website on Free Hosting with No Credential/Payment Forms = SAFE (0-10)
 */

import {
  BaseSecurityEvent,
  CorrelatedThreatAssessment,
  CorrelatedEvidence,
  ThreatSeverity,
  SecurityVerdict,
  PageBrandingEvent,
  FormSecurityEvent,
  NetworkSecurityEvent
} from './eventTypes';
import { isTrustedFederatedProvider } from '../config/trustedProviders';

export interface CorrelatorInput {
  tabId: number;
  url: string;
  domain: string;
  events: BaseSecurityEvent[];
  isAllowlisted?: boolean;
  isBlocklisted?: boolean;
  matchedBlocklistDomain?: string;
}

export function correlateSecurityEvents(
  inputOrTabId: CorrelatorInput | number,
  urlArg?: string,
  eventsArg?: BaseSecurityEvent[],
  isAllowlistedArg?: boolean,
  isBlocklistedArg?: boolean,
  matchedBlocklistDomainArg?: string
): CorrelatedThreatAssessment {
  let tabId = 0;
  let url = '';
  let domain = '';
  let events: BaseSecurityEvent[] = [];
  let isAllowlisted = false;
  let isBlocklisted = false;
  let matchedBlocklistDomain = '';

  if (typeof inputOrTabId === 'number') {
    tabId = inputOrTabId;
    url = typeof urlArg === 'string' ? urlArg : '';
    events = Array.isArray(eventsArg) ? eventsArg : [];
    isAllowlisted = !!isAllowlistedArg;
    isBlocklisted = !!isBlocklistedArg;
    matchedBlocklistDomain = typeof matchedBlocklistDomainArg === 'string' ? matchedBlocklistDomainArg : '';
    try {
      domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname.toLowerCase();
    } catch {
      domain = url.toLowerCase();
    }
  } else if (inputOrTabId && typeof inputOrTabId === 'object') {
    tabId = typeof inputOrTabId.tabId === 'number' ? inputOrTabId.tabId : 0;
    url = typeof inputOrTabId.url === 'string' ? inputOrTabId.url : '';
    domain = typeof inputOrTabId.domain === 'string' && inputOrTabId.domain ? inputOrTabId.domain.toLowerCase() : '';
    if (!domain && url) {
      try {
        domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname.toLowerCase();
      } catch {
        domain = url.toLowerCase();
      }
    }
    events = Array.isArray(inputOrTabId.events) ? inputOrTabId.events : [];
    isAllowlisted = !!inputOrTabId.isAllowlisted;
    isBlocklisted = !!inputOrTabId.isBlocklisted;
    matchedBlocklistDomain = typeof inputOrTabId.matchedBlocklistDomain === 'string' ? inputOrTabId.matchedBlocklistDomain : '';
  }

  const timestamp = Date.now();

  // 1. If explicitly allowlisted by user
  if (isAllowlisted) {
    return {
      tabId,
      url,
      domain,
      timestamp,
      score: 0,
      severity: 'SAFE',
      verdict: 'SAFE',
      evidence: [],
      signals: [],
      reasons: ['Domain is explicitly included in your trusted allowlist.'],
      eventsCount: events.length,
      timeline: events
    };
  }

  // 2. If explicitly matched on blocklist
  if (isBlocklisted) {
    const blockEvidence: CorrelatedEvidence[] = [{
      id: 'EV_BLOCKLIST',
      type: 'KNOWN_THREAT_DATABASE',
      severity: 'CRITICAL',
      weight: 98,
      title: 'Known Phishing Infrastructure Match',
      explanation: `Domain (${domain}) matches known malicious intelligence feed (${matchedBlocklistDomain || domain}).`
    }];
    return {
      tabId,
      url,
      domain,
      timestamp,
      score: 98,
      severity: 'CRITICAL',
      verdict: 'DANGEROUS',
      evidence: blockEvidence,
      signals: blockEvidence,
      reasons: [`Website matches confirmed phishing infrastructure database (${matchedBlocklistDomain || domain}).`],
      eventsCount: events.length,
      timeline: events
    };
  }

  const evidenceList: CorrelatedEvidence[] = [];
  const reasons: string[] = [];

  // Extract distinct event types
  const brandingEvents = events.filter((e): e is PageBrandingEvent => 
    e.type === 'BRAND_IDENTITY_DETECTED' || e.type === 'DOMAIN_MISMATCH_DETECTED' || e.type === 'FREE_HOSTING_DETECTED'
  );
  const formEvents = events.filter((e): e is FormSecurityEvent =>
    e.type === 'CREDENTIAL_FORM_DETECTED' ||
    e.type === 'PAYMENT_FORM_DETECTED' ||
    e.type === 'VERIFICATION_CODE_FORM_DETECTED' ||
    e.type === 'INSECURE_FORM_DETECTED' ||
    e.type === 'CROSS_ORIGIN_FORM_ACTION'
  );
  const networkEvents = events.filter((e): e is NetworkSecurityEvent =>
    e.type === 'NETWORK_REQUEST_OBSERVED' ||
    e.type === 'CROSS_ORIGIN_REQUEST_OBSERVED' ||
    e.type === 'CREDENTIAL_SUBMISSION_PATTERN'
  );
  const typosquatEvents = events.filter(e => e.type === 'TYPOSQUAT_DETECTED' || e.type === 'HOMOGLYPH_DETECTED');
  const redirectEvents = events.filter(e => e.type === 'REDIRECT_HOP_OBSERVED');
  const downloadEvents = events.filter(e => e.type === 'DOWNLOAD_TRIGGERED');
  const scarewareEvents = events.filter(e => e.type === 'SCAREWARE_CUE_DETECTED');

  // Check key behavioral indicators
  const officialBranding = brandingEvents.find(b => b.isOfficialDomain);
  const impersonatedBranding = brandingEvents.find(b => !b.isOfficialDomain);
  
  // Check if domain is a free hosting platform
  const isFreeHostingHost = impersonatedBranding?.isFreeHostingProvider || 
    /(\.netlify\.app|\.vercel\.app|\.firebaseapp\.com|\.web\.app|\.pages\.dev|\.workers\.dev|\.github\.io|\.gitlab\.io|\.render\.com|\.onrender\.com|\.surge\.sh|\.000webhostapp\.com)$/i.test(domain);

  const hasLoginForm = formEvents.some(f => f.hasPasswordField || f.formType === 'LOGIN');
  const hasPaymentForm = formEvents.some(f => f.hasCreditCardField || f.formType === 'PAYMENT');
  const has2FAForm = formEvents.some(f => f.has2FAField || f.formType === 'VERIFICATION_2FA');
  
  // Distinguish trusted federated form actions from rogue cross-origin form actions
  const rogueCrossOriginForm = formEvents.find(f => {
    if (!f.actionIsCrossOrigin) return false;
    const { isTrusted } = isTrustedFederatedProvider(f.actionHostname);
    return !isTrusted;
  });
  const hasCrossOriginFormAction = !!rogueCrossOriginForm;

  const hasInsecureForm = formEvents.some(f => f.actionIsInsecure);

  // Distinguish trusted network communication vs untrusted exfiltration
  const untrustedCrossOriginNetworkPost = networkEvents.find(n => {
    if (!n.isCrossOrigin || n.method !== 'POST') return false;
    const { isTrusted } = isTrustedFederatedProvider(n.destinationHostname);
    return !isTrusted;
  });
  const hasCrossOriginNetworkPost = !!untrustedCrossOriginNetworkPost;
  const hasSensitiveExfiltration = networkEvents.some(n => n.sensitiveSubmissionPattern);

  const isRawIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
  const hasTyposquat = typosquatEvents.length > 0;
  const hasMultiHopRedirect = redirectEvents.some(r => (r.evidence?.hopCount as number || 0) >= 3);
  const hasDangerousDownload = downloadEvents.some(d => d.severity === 'CRITICAL');
  const hasScareware = scarewareEvents.length > 0;

  // 3. Legitimate Verified Canonical Brand Dampening
  // e.g. vinted.com, paypal.com, accounts.google.com, github.com, developer.chrome.com
  if (officialBranding && !hasCrossOriginFormAction && !hasSensitiveExfiltration && !hasInsecureForm) {
    return {
      tabId,
      url,
      domain,
      timestamp,
      score: 2,
      severity: 'SAFE',
      verdict: 'SAFE',
      evidence: [{
        id: 'EV_OFFICIAL_BRAND',
        type: 'VERIFIED_CANONICAL_BRAND',
        severity: 'SAFE',
        weight: 0,
        title: `Verified ${officialBranding.claimedBrandName} Domain`,
        explanation: `Authentic official domain for ${officialBranding.claimedBrandName}.`
      }],
      reasons: [`Verified authentic website for ${officialBranding.claimedBrandName}.`],
      claimedBrand: {
        name: officialBranding.claimedBrandName,
        canonicalDomains: officialBranding.canonicalDomains,
        isImpersonated: false
      },
      eventsCount: events.length,
      timeline: events
    };
  }

  // 4. Multi-Signal Correlated Compound Rules
  let calculatedScore = 0;

  // RULE A: Brand Impersonation on Free Cloud Hosting (e.g., Vinted on Netlify, Jumia on Vercel, PayPal on Firebase)
  if (impersonatedBranding && (impersonatedBranding.isFreeHostingProvider || isFreeHostingHost)) {
    const brandName = impersonatedBranding.claimedBrandName;
    const providerName = impersonatedBranding.freeHostingProviderName || 'multi-tenant cloud hosting';
    let weight = 55;

    if (hasLoginForm) weight += 25;
    if (has2FAForm) weight += 15;
    if (hasPaymentForm) weight += 20;
    if (hasSensitiveExfiltration || hasCrossOriginNetworkPost || hasCrossOriginFormAction) weight += 15;

    calculatedScore = Math.max(calculatedScore, Math.min(98, weight));

    evidenceList.push({
      id: 'EV_BRAND_FREE_HOSTING',
      type: 'BRAND_IMPERSONATION_FREE_HOSTING',
      severity: 'CRITICAL',
      weight,
      title: `${brandName} Impersonation on Third-Party Hosting`,
      explanation: `Website presents ${brandName} branding while hosted on ${providerName} (${domain}) rather than official ${impersonatedBranding.canonicalDomains[0]}.`
    });

    reasons.push(`This site appears to impersonate ${brandName}.`);
    reasons.push(`Its domain (${domain}) is hosted on ${providerName} rather than official ${impersonatedBranding.canonicalDomains[0]}.`);
    if (hasLoginForm) reasons.push('An active credential or password form was detected.');
    if (has2FAForm) reasons.push('A two-factor verification passcode (2FA) prompt was detected.');
    if (hasSensitiveExfiltration || hasCrossOriginNetworkPost) reasons.push('Suspicious cross-origin data communication was observed.');
  }

  // RULE B: Brand Domain Mismatch on Generic Registered Domain (e.g. vintedmarket.com, paypal-verify.xyz)
  else if (impersonatedBranding && !isFreeHostingHost) {
    const brandName = impersonatedBranding.claimedBrandName;
    let weight = 45;

    if (hasLoginForm) weight += 30;
    if (has2FAForm) weight += 15;
    if (hasPaymentForm) weight += 20;
    if (hasCrossOriginFormAction || hasCrossOriginNetworkPost) weight += 15;

    calculatedScore = Math.max(calculatedScore, Math.min(95, weight));

    evidenceList.push({
      id: 'EV_BRAND_MISMATCH',
      type: 'BRAND_DOMAIN_MISMATCH',
      severity: 'HIGH',
      weight,
      title: `Brand Domain Mismatch (${brandName})`,
      explanation: `Website presents ${brandName} identity tokens on unrelated domain ${domain}.`
    });

    reasons.push(`This site claims to represent ${brandName}.`);
    reasons.push(`Its domain does not match ${brandName}'s official domain (${impersonatedBranding.canonicalDomains[0]}).`);
    if (hasLoginForm) reasons.push('Authentication credential fields are present.');
    if (hasCrossOriginFormAction) reasons.push('Form data is submitted to an external destination.');
  }

  // RULE C: Unbranded Payment / E-Commerce Collection on Free Hosting (e.g., random-shop.vercel.app)
  else if (isFreeHostingHost && (hasPaymentForm || hasLoginForm)) {
    let weight = 50;
    if (hasPaymentForm) weight += 15;
    if (hasLoginForm) weight += 10;
    if (hasCrossOriginFormAction || hasCrossOriginNetworkPost) weight += 15;

    calculatedScore = Math.max(calculatedScore, Math.min(85, weight));

    evidenceList.push({
      id: 'EV_FREE_HOSTING_SENSITIVE',
      type: 'UNVERIFIED_FINANCIAL_FREE_HOSTING',
      severity: 'HIGH',
      weight,
      title: 'Payment or Authentication on Free Subdomain',
      explanation: `Page collects payment details or credentials on multi-tenant free hosting (${domain}) without custom verified domain branding.`
    });

    reasons.push(`Sensitive financial or login information is requested on a multi-tenant cloud subdomain (${domain}).`);
    if (hasPaymentForm) reasons.push('Credit card or payment input fields were detected.');
    if (hasLoginForm) reasons.push('Password or login credential inputs were detected.');
  }

  // RULE D: Raw IP Hostname with Credential / Payment Fields (e.g. http://185.220.101.5/login.php)
  if (isRawIp && (hasLoginForm || hasPaymentForm || formEvents.length > 0)) {
    const weight = 90;
    calculatedScore = Math.max(calculatedScore, weight);

    evidenceList.push({
      id: 'EV_RAW_IP_AUTH',
      type: 'RAW_IP_CREDENTIAL_FORM',
      severity: 'CRITICAL',
      weight,
      title: 'Credential Entry on Bare IP Address',
      explanation: `Website requests sensitive authentication credentials directly on an IP address (${domain}) rather than a registered domain.`
    });

    reasons.push(`Website is hosted on a bare IP address (${domain}) without domain registration.`);
    reasons.push('Authentication credentials are requested directly on this IP host.');
  }

  // RULE E: Typosquatting / Visual Homoglyph with Credential Entry
  if (hasTyposquat) {
    const typoEv = typosquatEvents[0];
    let weight = 50;
    if (hasLoginForm) weight += 35;
    if (hasPaymentForm) weight += 25;

    calculatedScore = Math.max(calculatedScore, Math.min(96, weight));

    evidenceList.push({
      id: 'EV_TYPOSQUAT',
      type: 'TYPOSQUATTING_HOMOGLYPH',
      severity: 'CRITICAL',
      weight,
      title: typoEv.title,
      explanation: typoEv.description
    });

    if (!reasons.includes(typoEv.description)) {
      reasons.push(typoEv.description);
    }
  }

  // RULE F: Rogue Cross-Origin Credential Form Action
  if (hasCrossOriginFormAction && (hasLoginForm || hasPaymentForm || has2FAForm)) {
    const formEv = rogueCrossOriginForm!;
    const weight = 88;
    calculatedScore = Math.max(calculatedScore, weight);

    evidenceList.push({
      id: 'EV_CROSS_ORIGIN_FORM',
      type: 'CROSS_ORIGIN_CREDENTIAL_SUBMISSION',
      severity: 'CRITICAL',
      weight,
      title: 'Cross-Origin Credential Exfiltration Target',
      explanation: `Login form on ${domain} routes user credentials to an untrusted external domain (${formEv.actionHostname}).`
    });

    if (!reasons.some(r => r.includes('external destination') || r.includes('cross-origin'))) {
      reasons.push(`Form submits authentication credentials to an unrelated external domain (${formEv.actionHostname}).`);
    }
  }

  // RULE G: Insecure HTTP Credential Form
  if (hasInsecureForm && (hasLoginForm || hasPaymentForm)) {
    const weight = 78;
    calculatedScore = Math.max(calculatedScore, weight);

    evidenceList.push({
      id: 'EV_INSECURE_FORM',
      type: 'INSECURE_HTTP_CREDENTIAL_FORM',
      severity: 'HIGH',
      weight,
      title: 'Unencrypted Credential Form',
      explanation: 'Form transmits authentication credentials over unencrypted HTTP.'
    });

    reasons.push('Login credentials are submitted in cleartext over unencrypted HTTP.');
  }

  // RULE H: Coercive Scareware / Fake Tech Support Lockout
  if (hasScareware) {
    const weight = 82;
    calculatedScore = Math.max(calculatedScore, weight);

    evidenceList.push({
      id: 'EV_SCAREWARE',
      type: 'COERCIVE_SCAREWARE',
      severity: 'HIGH',
      weight,
      title: 'Coercive Social Engineering / Scareware',
      explanation: 'Page contains deceptive threat alerts, fake virus warnings, or urgency lockouts.'
    });

    reasons.push('Page displays coercive urgency or fake security alert warnings.');
  }

  // RULE I: Executable Download on High-Risk Site
  if (hasDangerousDownload) {
    const weight = 92;
    calculatedScore = Math.max(calculatedScore, weight);

    evidenceList.push({
      id: 'EV_DANGEROUS_DOWNLOAD',
      type: 'SUSPICIOUS_EXECUTABLE_DOWNLOAD',
      severity: 'CRITICAL',
      weight,
      title: 'Malicious Executable Download Attempt',
      explanation: 'Binary executable download triggered from high-risk origin.'
    });

    reasons.push('An executable file download was initiated from a suspicious webpage.');
  }

  // RULE J: Multi-hop Redirect Chain
  if (hasMultiHopRedirect && calculatedScore < 40) {
    calculatedScore = 48;
    evidenceList.push({
      id: 'EV_REDIRECT_TRAMPOLINE',
      type: 'REDIRECT_TRAMPOLINE',
      severity: 'MEDIUM',
      weight: 48,
      title: 'Multi-Hop Redirect Trampoline',
      explanation: 'Navigation routed through multiple intermediary URL shorteners.'
    });
    reasons.push('Navigation traversed an obfuscated multi-hop redirect chain.');
  }

  // Clean baseline if no suspicious indicators fired
  if (evidenceList.length === 0) {
    calculatedScore = 3;
    reasons.push('No brand spoofing, credential harvesting, or deceptive behaviors were observed.');
  }

  // 5. Final Score Clamping & Verdict Assignment
  const finalScore = Math.max(0, Math.min(100, Math.round(calculatedScore)));

  let severity: ThreatSeverity = 'SAFE';
  let verdict: SecurityVerdict = 'SAFE';

  if (finalScore >= 80) {
    severity = 'CRITICAL';
    verdict = 'DANGEROUS';
  } else if (finalScore >= 60) {
    severity = 'HIGH';
    verdict = 'HIGH_RISK';
  } else if (finalScore >= 40) {
    severity = 'MEDIUM';
    verdict = 'SUSPICIOUS';
  } else if (finalScore >= 20) {
    severity = 'LOW';
    verdict = 'LOW_RISK';
  } else {
    severity = 'SAFE';
    verdict = 'SAFE';
  }

  return {
    tabId,
    url,
    domain,
    timestamp,
    score: finalScore,
    severity,
    verdict,
    evidence: evidenceList,
    signals: evidenceList,
    reasons,
    claimedBrand: impersonatedBranding ? {
      name: impersonatedBranding.claimedBrandName,
      canonicalDomains: impersonatedBranding.canonicalDomains,
      isImpersonated: true
    } : undefined,
    eventsCount: events.length,
    timeline: events
  };
}
