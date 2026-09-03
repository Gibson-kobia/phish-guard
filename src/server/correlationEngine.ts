/**
 * PhishGuard Relational Compound Correlation Engine
 * 
 * Implements Compound Security Threat Correlation:
 * Evaluates relational combinations:
 * Third-party hosting + Brand impersonation + Credential/payment collection + Domain mismatch + Suspicious infrastructure + Threat intelligence = High Confidence
 * 
 * Crucial False Positive Rule:
 * "Netlify/Vercel = phishing" is FALSE.
 * A developer portfolio or static site on Vercel/Netlify with NO brand impersonation and NO login forms is safe (Score: 0).
 */

import {
  SecurityTelemetryRecord,
  SecurityIncident,
  DetectionSignal,
  ThreatSeverity,
  Verdict,
  SecurityActionTaken,
  IncidentSeverity,
  IncidentStatus,
  ThreatCategory,
  MitreTechnique,
  ThreatIntelReport
} from '../core/types';
import { KNOWN_BRANDS, FREE_HOSTING_PROVIDERS, extractRegisteredDomain } from '../core/engine/brandIdentity';
import { evaluateThreatIntelligence } from '../core/engine/threatIntelligence';

export interface TelemetryIngestPayload {
  event_type: 'page_analysis';
  url: string;
  domain?: string;
  title?: string;
  forms?: {
    password?: boolean;
    payment?: boolean;
    otp?: boolean;
    ssn?: boolean;
  };
  cross_origin_forms?: Array<{
    action: string;
    method?: string;
    is_cross_origin?: boolean;
    has_password?: boolean;
  }>;
  redirects?: string[];
  detected_brands?: string[];
  timestamp?: string | number;
}

export interface CorrelationResult {
  verdict: Verdict;
  severity: ThreatSeverity;
  score: number;
  confidence: number;
  action: SecurityActionTaken;
  incident: SecurityIncident | null;
  telemetryRecord: SecurityTelemetryRecord;
  signals: DetectionSignal[];
  mitreTechniques: string[];
  reasons: string[];
  explanation: {
    relationshipSummary: string;
    compoundingFactors: string[];
  };
}

export async function correlateBrowserTelemetry(payload: TelemetryIngestPayload): Promise<CorrelationResult> {
  const now = Date.now();
  const rawUrl = payload.url;

  let domain = payload.domain || '';
  if (!domain) {
    try {
      const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
      domain = parsed.hostname.toLowerCase();
    } catch {
      domain = rawUrl.toLowerCase();
    }
  } else {
    domain = domain.toLowerCase();
  }

  const registeredDomain = extractRegisteredDomain(domain);
  const pageTitle = payload.title || '';
  const hasPassword = !!payload.forms?.password;
  const hasPayment = !!payload.forms?.payment;
  const hasOtp = !!payload.forms?.otp;
  const hasCredentialCollection = hasPassword || hasPayment || hasOtp;

  const crossOriginForms = payload.cross_origin_forms || [];
  const hasRogueCrossOrigin = crossOriginForms.some(f => f.is_cross_origin && f.has_password);

  // 1. Check Third-party Hosting
  let isFreeHosting = false;
  let freeHostingProvider: string | null = null;

  for (const [provider, pattern] of Object.entries(FREE_HOSTING_PROVIDERS)) {
    if (domain.includes(pattern)) {
      isFreeHosting = true;
      freeHostingProvider = provider;
      break;
    }
  }

  // 2. Identify Brand Candidate & Mismatch
  let targetBrandName: string | null = null;
  let matchedBrandObj: (typeof KNOWN_BRANDS)[0] | undefined;
  let isOfficialBrandDomain = false;
  let isBrandMismatch = false;

  const domainWithoutDots = domain.replace(/\./g, '');
  for (const brand of KNOWN_BRANDS) {
    const isNameInDomain = domainWithoutDots.includes(brand.name.toLowerCase().replace(/[^a-z0-9]/g, ''));
    const isKeywordInDomain = brand.keywords.some(kw => domain.includes(kw));
    const isTitleMatch = pageTitle.toLowerCase().includes(brand.name.toLowerCase());

    if (isNameInDomain || isKeywordInDomain || isTitleMatch) {
      matchedBrandObj = brand;
      targetBrandName = brand.name;
      isOfficialBrandDomain = brand.canonicalDomains.some(cd => registeredDomain === cd || domain.endsWith('.' + cd));
      break;
    }
  }

  if (matchedBrandObj) {
    targetBrandName = matchedBrandObj.name;
    if (!isOfficialBrandDomain) {
      isBrandMismatch = true;
    }
  } else if ((payload.detected_brands && payload.detected_brands.length > 0) || pageTitle) {
    const declared = payload.detected_brands?.[0] || '';
    if (declared && !domain.includes(declared.toLowerCase().replace(/[^a-z0-9]/g, ''))) {
      targetBrandName = declared;
      isBrandMismatch = true;
    }
  }

  // 3. Check Suspicious Infrastructure (Raw IP, High-Risk TLD, Insecure HTTP)
  const isRawIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
  const isPunycode = domain.includes('xn--');
  const highRiskTlds = ['.top', '.xyz', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.rest', '.quest', '.cam'];
  const isHighRiskTld = highRiskTlds.some(tld => domain.endsWith(tld));
  const isInsecureHttp = rawUrl.startsWith('http://');

  // 4. Query Threat Intelligence Feeds
  let threatIntelReport: ThreatIntelReport = {
    overallVerdict: 'CLEAN',
    maxScoreContribution: 0,
    providersCount: 5,
    flaggedCount: 0,
    results: [],
    cached: false,
    queriedAt: now
  };

  try {
    threatIntelReport = await evaluateThreatIntelligence(rawUrl, domain);
  } catch {
    // Non-blocking failover
  }

  // 5. RELATIONAL COMPOUND CORRELATION ENGINE
  const signals: DetectionSignal[] = [];
  const mitreTechniques: string[] = [];
  const compoundingFactors: string[] = [];
  let score = 0;
  let confidence = 0.90;

  // SCENARIO EVALUATION:

  // Rule A: Safe Baseline - Benign Developer / Static Site on Netlify/Vercel
  if (isFreeHosting && !targetBrandName && !hasCredentialCollection && !isRawIp && threatIntelReport.overallVerdict === 'CLEAN') {
    score = 0;
    confidence = 0.95;
    compoundingFactors.push('Developer/Static site on third-party cloud hosting with no authentication or payment requests');
  } 
  // Rule B: Official Canonical Domain with legitimate authentication
  else if (isOfficialBrandDomain && !isHighRiskTld && !isRawIp) {
    score = 2;
    confidence = 0.99;
    compoundingFactors.push(`Verified official domain for ${targetBrandName}`);
  }
  // Rule C: High-Confidence Phishing Compound Combination
  // Third-party hosting + Brand impersonation + Credential/payment collection + Domain mismatch
  else if (isFreeHosting && isBrandMismatch && hasCredentialCollection) {
    score = 100;
    confidence = 0.99;
    mitreTechniques.push('T1584.004', 'T1598.003', 'T1566.002', 'T1036.007');

    signals.push({
      id: 'SIG-BRAND-FREE-HOSTING',
      category: 'TYPOSQUATTING',
      type: 'BRAND_IMPERSONATION_FREE_HOSTING',
      severity: 'CRITICAL',
      weight: 50,
      title: `${targetBrandName} Impersonation on ${freeHostingProvider || 'Free Cloud Hosting'}`,
      description: `The website presents ${targetBrandName} branding on multi-tenant cloud hosting (${domain}) rather than official ${matchedBrandObj?.canonicalDomains[0] || 'canonical domain'}.`,
      confidence: 0.99,
      evidence: { targetBrand: targetBrandName, freeHostingProvider, domain }
    });

    signals.push({
      id: 'SIG-CREDENTIAL-FORM',
      category: 'DOM_SECURITY',
      type: hasPayment ? 'FINANCIAL_DATA_COLLECTION' : 'CREDENTIAL_INPUT_FIELD',
      severity: 'CRITICAL',
      weight: 35,
      title: hasPayment ? 'Payment & Financial Data Harvesting Form' : 'Active Credential & Password Form',
      description: hasPayment
        ? 'Form explicitly collects payment card numbers and billing identity.'
        : 'Authentication form prompts for passwords/verification codes on unverified domain.',
      confidence: 0.98
    });

    signals.push({
      id: 'SIG-COMPOUND-CORRELATION',
      category: 'TYPOSQUATTING',
      type: 'COMPOUND_SPOOF_LOGIN_RISK',
      severity: 'CRITICAL',
      weight: 40,
      title: 'Compound Weaponized Phishing Infrastructure',
      description: `Synergistic correlation confirmed: Third-party hosting (${freeHostingProvider || 'Cloud'}) + Brand impersonation (${targetBrandName}) + Active credential harvesting + Domain mismatch.`,
      confidence: 0.99
    });

    compoundingFactors.push(
      `Third-party hosting (${freeHostingProvider || 'Free Host'})`,
      `Brand impersonation (${targetBrandName})`,
      hasPayment ? 'Payment data harvesting' : 'Password credential harvesting',
      'Domain mismatch against canonical records'
    );
  }
  // Rule D: Brand impersonation without credential form on free host
  else if (isFreeHosting && isBrandMismatch && !hasCredentialCollection) {
    score = 55;
    confidence = 0.88;
    mitreTechniques.push('T1036.007');

    signals.push({
      id: 'SIG-BRAND-SUSPICIOUS-HOST',
      category: 'TYPOSQUATTING',
      type: 'BRAND_IMPERSONATION_FREE_HOSTING',
      severity: 'HIGH',
      weight: 45,
      title: `Potential ${targetBrandName} Brand Impersonation on Cloud Hosting`,
      description: `The page mimics ${targetBrandName} on cloud hosting (${domain}) but does not currently present active login inputs.`,
      confidence: 0.88
    });

    compoundingFactors.push(`Third-party hosting (${freeHostingProvider})`, `Brand name presence (${targetBrandName}) without active forms`);
  }
  // Rule E: Raw IPv4 with Credential Form
  else if (isRawIp && hasCredentialCollection) {
    score = 98;
    confidence = 0.98;
    mitreTechniques.push('T1584.004', 'T1598.003');

    signals.push({
      id: 'SIG-IP-LOGIN',
      category: 'DOM_SECURITY',
      type: 'COMPOUND_IP_LOGIN_RISK',
      severity: 'CRITICAL',
      weight: 70,
      title: 'Credential Entry on Bare IP Hostname',
      description: 'Authentication form hosted directly on raw IPv4 address without registered domain name.',
      confidence: 0.97
    });

    compoundingFactors.push('Direct raw IPv4 address hosting', 'Password/credential submission form');
  }
  // Rule F: Brand Lookalike / Homoglyph with Credential Harvesting
  else if (isBrandMismatch && hasCredentialCollection) {
    score = 90;
    confidence = 0.96;
    mitreTechniques.push('T1036.007', 'T1598.003', 'T1566.002');

    signals.push({
      id: 'SIG-BRAND-MISMATCH-LOGIN',
      category: 'TYPOSQUATTING',
      type: 'BRAND_DOMAIN_MISMATCH',
      severity: 'CRITICAL',
      weight: 55,
      title: `Brand Mismatch (${targetBrandName}) with Login Form`,
      description: `Domain ${domain} claims to be ${targetBrandName} and requests credentials.`,
      confidence: 0.96
    });

    compoundingFactors.push(`Brand mismatch (${targetBrandName})`, 'Password/credential harvesting form');
  }

  // Threat Intelligence Feed Check
  if (threatIntelReport.overallVerdict === 'MALICIOUS' || threatIntelReport.overallVerdict === 'SUSPICIOUS') {
    score = Math.max(score, 85);
    mitreTechniques.push('T1566.002');
    signals.push({
      id: 'SIG-THREAT-INTEL',
      category: 'REPUTATION',
      type: 'REPUTATION_DATABASE_MATCH',
      severity: 'CRITICAL',
      weight: 60,
      title: 'Threat Intelligence Multi-Feed Detection',
      description: `Domain listed across verified threat repositories (${threatIntelReport.flaggedCount}/${threatIntelReport.providersCount} providers).`,
      confidence: 0.99
    });
    compoundingFactors.push('Multi-source threat intelligence feed hit');
  }

  // Cross-origin data exfiltration penalty
  if (hasRogueCrossOrigin) {
    score = Math.max(score, 85);
    mitreTechniques.push('T1056.004');
    signals.push({
      id: 'SIG-CROSS-ORIGIN',
      category: 'DOM_SECURITY',
      type: 'CROSS_ORIGIN_CREDENTIAL_HARVESTER',
      severity: 'CRITICAL',
      weight: 60,
      title: 'Cross-Origin Credential Form Submission',
      description: 'Form transmits entered authentication credentials to an external destination.',
      confidence: 0.97
    });
    compoundingFactors.push('External cross-origin POST exfiltration');
  }

  // Determine Verdict and Action
  let verdict: Verdict = 'SAFE';
  let severity: ThreatSeverity = 'SAFE';
  let incidentSeverity: IncidentSeverity = 'LOW';
  let action: SecurityActionTaken = 'SILENT_MONITORING';

  if (score >= 80) {
    verdict = 'DANGEROUS';
    severity = 'CRITICAL';
    incidentSeverity = 'CRITICAL';
    action = hasCredentialCollection ? 'FORM_SUBMISSION_INTERCEPTED' : 'BLOCKING_MODAL';
  } else if (score >= 60) {
    verdict = 'HIGH_RISK';
    severity = 'HIGH';
    incidentSeverity = 'HIGH';
    action = 'IN_PAGE_BANNER';
  } else if (score >= 40) {
    verdict = 'SUSPICIOUS';
    severity = 'MEDIUM';
    incidentSeverity = 'MEDIUM';
    action = 'IN_PAGE_BANNER';
  } else if (score >= 20) {
    verdict = 'LOW_RISK';
    severity = 'LOW';
    incidentSeverity = 'LOW';
    action = 'SILENT_MONITORING';
  } else {
    verdict = 'SAFE';
    severity = 'SAFE';
    incidentSeverity = 'LOW';
    action = 'SILENT_MONITORING';
  }

  // Reasons list
  const reasons: string[] = [];
  if (signals.length === 0) {
    reasons.push('No deceptive branding, rogue forms, or known threat signals were detected.');
  } else {
    for (const sig of signals) {
      reasons.push(sig.description);
    }
  }

  // Generate Incident ID if actionable threat
  let incident: SecurityIncident | null = null;
  let incidentId: string | undefined;

  const mitreTechniqueObjects: MitreTechnique[] = Array.from(new Set(mitreTechniques)).map(id => ({
    id,
    name: id === 'T1584.004' ? 'Compromise Infrastructure: Free Hosting' :
          id === 'T1598.003' ? 'Phishing for Information: Spearphishing Link' :
          id === 'T1036.007' ? 'Masquerading: Double File Extension / Name' : 'Phishing',
    tactic: 'Initial Access'
  }));

  if (verdict === 'DANGEROUS' || verdict === 'HIGH_RISK') {
    const randomHex = Math.floor(Math.random() * 9000 + 1000).toString();
    incidentId = `INC-2026-${randomHex}`;

    let threatCategory: ThreatCategory = 'BRAND_IMPERSONATION';
    if (hasPayment) threatCategory = 'PAYMENT_FRAUD';
    else if (hasPassword) threatCategory = 'CREDENTIAL_HARVESTING';

    incident = {
      incidentId,
      title: `${verdict}: ${domain} (${targetBrandName ? targetBrandName + ' Spoof' : 'Suspicious Endpoint'})`,
      threatCategory,
      severity: incidentSeverity,
      status: 'ACTIVE',
      riskScore: score,
      affectedDomain: domain,
      targetBrand: targetBrandName || undefined,
      createdAt: now,
      updatedAt: now,
      mitreTechniques: mitreTechniqueObjects,
      iocs: [
        {
          type: 'DOMAIN',
          value: domain,
          description: `Flagged destination host`,
          confidence: 'HIGH'
        },
        {
          type: 'URL',
          value: rawUrl,
          description: `Analysis target URL`,
          confidence: 'HIGH'
        }
      ],
      telemetryLogIds: [],
      analystNotes: [
        {
          id: `NOTE-${now}`,
          author: 'PhishGuard Correlation Engine',
          timestamp: now,
          text: `Correlated ${signals.length} signals. Factors: ${compoundingFactors.join(', ')}.`
        }
      ],
      recommendedMitigations: [
        'Enforce domain-level DNS block',
        'Revoke entered credentials if submitted',
        'Submit takedown request to hosting provider'
      ]
    };
  }

  // Build Telemetry Record
  const analysisId = `analysis_${now}_${Math.random().toString(36).substring(2, 7)}`;
  const telemetryId = `tel_${Math.floor(now / 1000)}_${Math.random().toString(36).substring(2, 6)}`;

  const telemetryRecord: SecurityTelemetryRecord = {
    id: telemetryId,
    analysisId,
    timestamp: now,
    timeIso: new Date(now).toISOString(),
    url: rawUrl,
    domain,
    tld: domain.split('.').pop() || '',
    pageRiskScore: score,
    verdict,
    severity,
    confidence,
    extensionVersion: '1.0.0',
    detectedSignals: signals,
    brandCandidates: targetBrandName ? [{
      name: targetBrandName,
      confidence: 0.95,
      isImpersonated: isBrandMismatch,
      canonicalDomains: matchedBrandObj?.canonicalDomains || [],
      evidence: compoundingFactors
    }] : [],
    infrastructureSignals: {
      isIpAddress: isRawIp,
      isPunycode,
      isFreeHosting,
      freeHostingProvider,
      hasSuspiciousPort: false,
      hasHighRiskTld: isHighRiskTld,
      subdomainDepth: domain.split('.').length,
      entropyScore: 3.2,
      length: domain.length
    },
    threatIntelligence: threatIntelReport,
    formRiskIndicators: {
      formsCount: (payload.forms ? 1 : 0) + crossOriginForms.length,
      hasPasswordInput: hasPassword,
      hasCreditCardInput: hasPayment,
      hasSsnInput: !!payload.forms?.ssn,
      has2FAInput: hasOtp,
      hasHiddenCredentialFields: false,
      suspiciousFormActions: crossOriginForms.map(f => ({
        actionHost: f.action,
        isCrossOrigin: !!f.is_cross_origin,
        isInsecureHttp: f.action.startsWith('http://'),
        hasPasswordField: !!f.has_password,
        method: f.method || 'POST'
      }))
    },
    crossOriginBehavior: {
      hasCrossOriginPost: crossOriginForms.some(f => f.is_cross_origin),
      hasCrossOriginCredentialTarget: hasRogueCrossOrigin,
      observedDestinations: crossOriginForms.map(f => f.action)
    },
    redirectInformation: {
      hopCount: payload.redirects?.length || 1,
      hasShortener: false,
      hasCrossDomainRedirect: false,
      hops: (payload.redirects || []).map(r => ({
        url: r,
        hostname: domain
      }))
    },
    actionTaken: action,
    wasWarningDisplayed: action === 'IN_PAGE_BANNER' || action === 'BLOCKING_MODAL' || action === 'FORM_SUBMISSION_INTERCEPTED',
    wasDangerousFormBlocked: action === 'FORM_SUBMISSION_INTERCEPTED',
    incidentId,
    targetBrandName: targetBrandName || undefined,
    reasons
  };

  return {
    verdict,
    severity,
    score,
    confidence,
    action,
    incident,
    telemetryRecord,
    signals,
    mitreTechniques: Array.from(new Set(mitreTechniques)),
    reasons,
    explanation: {
      relationshipSummary: compoundingFactors.join(' + ') || 'Clean baseline',
      compoundingFactors
    }
  };
}
