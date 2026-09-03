import {
  SecurityAnalysisResult,
  DetectionSignal,
  SecurityEvidenceItem,
  ThreatSeverity,
  Verdict,
  ExtensionSettings,
  FormAnalysisMetadata,
  RedirectAnalysisData,
  SocialEngineeringMetadata,
  DownloadSecurityContext
} from '../types';
import { extractUrlFeatures } from './urlAnalysis';
import { analyzeTyposquatting } from './typosquatting';
import { evaluateBrandImpersonation, extractRegisteredDomain } from './brandIdentity';
import { evaluateFormSecurity } from './formAnalysis';
import { evaluateSocialEngineering } from './socialEngineering';
import { evaluateDownloadContext } from './downloads';
import { analyzeRedirectChain } from './redirectAnalysis';
import { checkDomainReputation } from './reputation';
import { buildSecurityTimeline } from './timeline';
import {
  DEFAULT_SETTINGS,
  SENSITIVITY_MULTIPLIERS,
  COMPOUND_PENALTY_TYPOSQUAT_LOGIN,
  COMPOUND_PENALTY_IP_LOGIN,
  COMPOUND_PENALTY_CROSS_ORIGIN,
  COMPOUND_PENALTY_SOCENG_LOGIN,
  LEGITIMATE_BRAND_DAMPENER_FACTOR
} from '../config/rules';

/**
 * Main Detection Orchestrator:
 * Executes multi-signal security evaluation, derives explainable evidence,
 * generates chronological security timeline, and produces calibrated 5-tier risk assessment.
 */
export function analyzePageSecurity(
  rawUrl: string,
  formMetadata?: FormAnalysisMetadata | null,
  redirectData?: RedirectAnalysisData | null,
  customSettings?: Partial<ExtensionSettings>,
  socialMeta?: SocialEngineeringMetadata | null,
  downloadContext?: DownloadSecurityContext | null
): SecurityAnalysisResult {
  const startTime = performance.now();
  const settings: ExtensionSettings = { ...DEFAULT_SETTINGS, ...customSettings };
  
  let domain = '';
  try {
    const parsed = new URL(rawUrl.startsWith('http') ? rawUrl : 'https://' + rawUrl);
    domain = parsed.hostname.toLowerCase();
  } catch {
    domain = rawUrl.toLowerCase();
  }

  // If protection is explicitly toggled off
  if (settings.protectionEnabled === false) {
    const timeline = buildSecurityTimeline({
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      verdict: 'SAFE',
      severity: 'SAFE',
      signals: [],
      isAllowlisted: true
    });

    return {
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      severity: 'SAFE',
      verdict: 'SAFE',
      signals: [],
      evidenceItems: [],
      timeline,
      reasons: ['PhishGuard real-time protection is currently disabled by user configuration.'],
      scanDurationMs: Math.round(performance.now() - startTime),
      features: {
        reputation: { isAllowlisted: false, isBlocklisted: false }
      }
    };
  }

  // 1. Check Reputation Layer
  const reputation = settings.enableReputationLayer
    ? checkDomainReputation(domain, settings.allowlist, settings.blocklist)
    : { isAllowlisted: false, isBlocklisted: false, signals: [] };

  // If Domain is explicitly allowlisted, immediately return SAFE with timeline
  if (reputation.isAllowlisted) {
    const timeline = buildSecurityTimeline({
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      verdict: 'SAFE',
      severity: 'SAFE',
      signals: [],
      isAllowlisted: true
    });

    return {
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      severity: 'SAFE',
      verdict: 'SAFE',
      signals: [],
      evidenceItems: [],
      timeline,
      reasons: ['Domain is explicitly included in the user trusted allowlist.'],
      scanDurationMs: Math.round(performance.now() - startTime),
      features: {
        reputation: {
          isAllowlisted: true,
          isBlocklisted: false,
          matchedDomain: reputation.matchedDomain
        }
      }
    };
  }

  // 2. URL Structural Analysis
  const { features: urlFeatures, signals: urlSignals } = settings.enableUrlAnalysis
    ? extractUrlFeatures(rawUrl)
    : { features: undefined, signals: [] };

  // 3. Typosquatting & Homoglyph Analysis
  const typosquatResult = settings.enableTyposquatting
    ? analyzeTyposquatting(domain, settings.protectedBrands)
    : { signals: [], targetBrand: undefined, isLegitimateBrand: false };

  // 3b. Brand Impersonation & Free Hosting Abuse Analysis
  const pageTitle = formMetadata?.pageTitle || '';
  const visibleHeadings = socialMeta?.visibleHeadingsSample || [];
  const brandEval = evaluateBrandImpersonation(domain, pageTitle, visibleHeadings, formMetadata, socialMeta);
  const brandSignals: DetectionSignal[] = [];

  if (brandEval && !brandEval.isOfficial) {
    if (brandEval.isFreeHostingAbuse) {
      brandSignals.push({
        id: 'SIGNAL_BRAND_FREE_HOSTING',
        category: 'TYPOSQUATTING',
        type: 'BRAND_IMPERSONATION_FREE_HOSTING',
        severity: 'CRITICAL',
        weight: 50,
        title: `${brandEval.brand.name} Impersonation on Free Hosting`,
        description: `The website presents ${brandEval.brand.name} branding on third-party cloud infrastructure (${brandEval.freeHostingProvider}) rather than official ${brandEval.brand.canonicalDomains[0]}.`,
        confidence: 0.98,
        evidence: {
          brand: brandEval.brand.name,
          freeHostingProvider: brandEval.freeHostingProvider,
          domain
        }
      });
    } else {
      brandSignals.push({
        id: 'SIGNAL_BRAND_MISMATCH',
        category: 'TYPOSQUATTING',
        type: 'BRAND_DOMAIN_MISMATCH',
        severity: 'HIGH',
        weight: 40,
        title: `Brand Domain Mismatch (${brandEval.brand.name})`,
        description: `Page appears to represent ${brandEval.brand.name}, but hostname (${domain}) does not match official ${brandEval.brand.canonicalDomains[0]}.`,
        confidence: 0.95,
        evidence: {
          brand: brandEval.brand.name,
          domain
        }
      });
    }
  }

  // 4. Form & DOM Analysis
  const formSignals = (settings.enableDomAnalysis && formMetadata)
    ? evaluateFormSecurity(rawUrl, formMetadata)
    : [];

  // 5. Social Engineering Analysis
  const socialSignals = (settings.enableSocialEngineering && socialMeta)
    ? evaluateSocialEngineering(socialMeta)
    : [];

  // 6. Download Context Analysis
  const downloadSignals = (settings.enableDownloadContext && downloadContext)
    ? evaluateDownloadContext(downloadContext)
    : [];

  // 7. Redirect Chain Analysis
  const redirectSignals = (settings.enableRedirectAnalysis && redirectData)
    ? analyzeRedirectChain(redirectData)
    : [];

  // Combine all active signals
  const allSignals: DetectionSignal[] = [
    ...reputation.signals,
    ...urlSignals,
    ...typosquatResult.signals,
    ...brandSignals,
    ...formSignals,
    ...socialSignals,
    ...downloadSignals,
    ...redirectSignals
  ];

  // 8. Compound Risk Interaction Modifiers
  const hasTyposquatOrHomoglyph = typosquatResult.signals.some(
    s => s.type === 'HOMOGLYPH_SUBSTITUTION' || s.type === 'TYPOSQUAT_DISTANCE_1' || s.type === 'BRAND_COMBOSQUATTING'
  ) || brandSignals.length > 0;
  const hasCredentialField = formSignals.some(
    s => s.type === 'CREDENTIAL_INPUT_FIELD' || s.type === 'FINANCIAL_DATA_COLLECTION'
  ) || formMetadata?.hasPasswordInput || formMetadata?.hasCreditCardInput || formMetadata?.has2FAInput;
  const isIpAddress = urlSignals.some(s => s.type === 'IP_ADDRESS_HOSTNAME');
  const isCrossOriginHarvest = formSignals.some(s => s.type === 'CROSS_ORIGIN_CREDENTIAL_HARVESTER');
  const isSuspiciousTld = urlSignals.some(s => s.type === 'HIGH_RISK_TOP_LEVEL_DOMAIN');
  const hasSocialUrgency = socialSignals.some(
    s => s.type === 'COERCIVE_URGENCY_WARNING' || s.type === 'FAKE_TECH_SUPPORT_SCAM'
  );

  // Brand Impersonation / Typosquat + Password/Credential Form
  if (hasTyposquatOrHomoglyph && hasCredentialField) {
    allSignals.push({
      id: 'SIGNAL_COMPOUND_TYPO_LOGIN',
      category: 'TYPOSQUATTING',
      type: 'COMPOUND_SPOOF_LOGIN_RISK',
      severity: 'CRITICAL',
      weight: COMPOUND_PENALTY_TYPOSQUAT_LOGIN,
      title: 'Active Credential Form on Lookalike / Impersonated Domain',
      description: 'The webpage combines a brand lookalike or impersonated domain with an active authentication/verification form. This combination strongly correlates with phishing kit deployments.',
      confidence: 0.98
    });
  }

  // Raw IP + Password Input Form
  if (isIpAddress && hasCredentialField) {
    allSignals.push({
      id: 'SIGNAL_COMPOUND_IP_LOGIN',
      category: 'DOM_SECURITY',
      type: 'COMPOUND_IP_LOGIN_RISK',
      severity: 'CRITICAL',
      weight: COMPOUND_PENALTY_IP_LOGIN,
      title: 'Credential Entry Requested on Direct IP Hostname',
      description: 'The website requests sensitive user authentication credentials while hosted on a bare IP address rather than a registered secure domain.',
      confidence: 0.97
    });
  }

  // Cross-Origin Form + High Risk TLD
  if (isCrossOriginHarvest && isSuspiciousTld) {
    allSignals.push({
      id: 'SIGNAL_COMPOUND_CROSS_TLD',
      category: 'DOM_SECURITY',
      type: 'COMPOUND_CROSS_TLD_RISK',
      severity: 'HIGH',
      weight: COMPOUND_PENALTY_CROSS_ORIGIN,
      title: 'Cross-Origin Form on High-Risk TLD',
      description: 'Form submission transfers data across domains on an unregistered/high-risk top-level domain.',
      confidence: 0.90
    });
  }

  // Social Urgency + Credential/Payment Form
  if (hasSocialUrgency && hasCredentialField) {
    allSignals.push({
      id: 'SIGNAL_COMPOUND_SOCENG_LOGIN',
      category: 'SOCIAL_ENGINEERING',
      type: 'COMPOUND_SOCENG_LOGIN_RISK',
      severity: 'CRITICAL',
      weight: COMPOUND_PENALTY_SOCENG_LOGIN,
      title: 'Coercive Urgency Combined with Credential Request',
      description: 'The page combines coercive suspension/urgency language with sensitive login or credential inputs.',
      confidence: 0.95
    });
  }

  // 9. Base Score Calculation
  let baseScore = allSignals.reduce((sum, s) => sum + s.weight, 0);

  // If this is a canonical, verified legitimate brand domain, dampen any false generic signals
  const isOfficialBrand = typosquatResult.isLegitimateBrand || (brandEval && brandEval.isOfficial);
  if (isOfficialBrand) {
    baseScore = Math.round(baseScore * LEGITIMATE_BRAND_DAMPENER_FACTOR);
  }

  // 10. Sensitivity Multiplier
  const multiplier = SENSITIVITY_MULTIPLIERS[settings.detectionSensitivity] || 1.0;
  const rawScore = Math.round(baseScore * multiplier);

  // 11. Score Clamping (0 to 100)
  const score = Math.max(0, Math.min(100, rawScore));

  // 12. 5-Tier Verdict & Severity Classification
  // 0-19: SAFE, 20-39: LOW_RISK, 40-59: SUSPICIOUS, 60-79: HIGH_RISK, 80-100: DANGEROUS/CRITICAL
  let severity: ThreatSeverity = 'SAFE';
  let verdict: Verdict = 'SAFE';

  if (score >= 80) {
    severity = 'CRITICAL';
    verdict = 'DANGEROUS';
  } else if (score >= 60) {
    severity = 'HIGH';
    verdict = 'HIGH_RISK';
  } else if (score >= 40) {
    severity = 'MEDIUM';
    verdict = 'SUSPICIOUS';
  } else if (score >= 20) {
    severity = 'LOW';
    verdict = 'LOW_RISK';
  } else {
    severity = 'SAFE';
    verdict = 'SAFE';
  }

  // 13. Generate Structured Evidence Items (Non-mathematical explanations for consumers)
  const evidenceItems: SecurityEvidenceItem[] = allSignals.map(sig => ({
    id: sig.id,
    category: sig.category,
    severity: sig.severity,
    weight: sig.weight,
    summary: sig.title,
    explanation: sig.description
  }));

  // 14. Generate Human-Readable Reasons
  const reasons: string[] = [];
  if (reputation.isBlocklisted) {
    reasons.push(`Domain is flagged on local threat blocklists (${reputation.matchedDomain}).`);
  }
  if (allSignals.length === 0) {
    reasons.push('No suspicious heuristics, typosquats, or deceptive form behaviors were detected.');
  } else {
    // Sort signals by weight descending for top actionable reasons
    const topSignals = [...allSignals].sort((a, b) => b.weight - a.weight).slice(0, 4);
    for (const sig of topSignals) {
      reasons.push(sig.description);
    }
  }

  // 15. Build Chronological Security Timeline
  const timeline = buildSecurityTimeline({
    url: rawUrl,
    domain,
    timestamp: Date.now(),
    score,
    verdict,
    severity,
    signals: allSignals,
    formMeta: formMetadata,
    redirectData,
    socialMeta,
    downloadContext,
    isAllowlisted: reputation.isAllowlisted,
    isBlocklisted: reputation.isBlocklisted
  });

  const duration = Math.round(performance.now() - startTime);

  return {
    url: rawUrl,
    domain,
    timestamp: Date.now(),
    score,
    severity,
    verdict,
    signals: allSignals,
    evidenceItems,
    timeline,
    reasons,
    targetBrand: typosquatResult.targetBrand,
    scanDurationMs: duration,
    features: {
      url: urlFeatures,
      form: formMetadata,
      social: socialMeta,
      redirect: redirectData,
      download: downloadContext,
      reputation: {
        isAllowlisted: reputation.isAllowlisted,
        isBlocklisted: reputation.isBlocklisted,
        matchedDomain: reputation.matchedDomain
      }
    }
  };
}
