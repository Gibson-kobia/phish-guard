import { extractUrlFeatures } from './urlAnalysis.js';
import { analyzeTyposquatting } from './typosquatting.js';
import { evaluateBrandImpersonation } from './brandIdentity.js';
import { evaluateFormSecurity } from './formAnalysis.js';
import { evaluateSocialEngineering } from './socialEngineering.js';
import { evaluateDownloadContext } from './downloads.js';
import { analyzeRedirectChain } from './redirectAnalysis.js';
import { checkDomainReputation } from './reputation.js';
import { buildSecurityTimeline } from './timeline.js';
import {
  DEFAULT_SETTINGS,
  SENSITIVITY_MULTIPLIERS,
  COMPOUND_PENALTY_TYPOSQUAT_LOGIN,
  COMPOUND_PENALTY_IP_LOGIN,
  COMPOUND_PENALTY_CROSS_ORIGIN,
  COMPOUND_PENALTY_SOCENG_LOGIN,
  LEGITIMATE_BRAND_DAMPENER_FACTOR
} from '../config/rules.js';
function analyzePageSecurity(rawUrl, formMetadata, redirectData, customSettings, socialMeta, downloadContext) {
  const startTime = performance.now();
  const settings = { ...DEFAULT_SETTINGS, ...customSettings };
  let domain = "";
  try {
    const parsed = new URL(rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl);
    domain = parsed.hostname.toLowerCase();
  } catch {
    domain = rawUrl.toLowerCase();
  }
  if (settings.protectionEnabled === false) {
    const timeline2 = buildSecurityTimeline({
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      verdict: "SAFE",
      severity: "SAFE",
      signals: [],
      isAllowlisted: true
    });
    return {
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      severity: "SAFE",
      verdict: "SAFE",
      signals: [],
      evidenceItems: [],
      timeline: timeline2,
      reasons: ["PhishGuard real-time protection is currently disabled by user configuration."],
      scanDurationMs: Math.round(performance.now() - startTime),
      features: {
        reputation: { isAllowlisted: false, isBlocklisted: false }
      }
    };
  }
  const reputation = settings.enableReputationLayer ? checkDomainReputation(domain, settings.allowlist, settings.blocklist) : { isAllowlisted: false, isBlocklisted: false, signals: [] };
  if (reputation.isAllowlisted) {
    const timeline2 = buildSecurityTimeline({
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      verdict: "SAFE",
      severity: "SAFE",
      signals: [],
      isAllowlisted: true
    });
    return {
      url: rawUrl,
      domain,
      timestamp: Date.now(),
      score: 0,
      severity: "SAFE",
      verdict: "SAFE",
      signals: [],
      evidenceItems: [],
      timeline: timeline2,
      reasons: ["Domain is explicitly included in the user trusted allowlist."],
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
  const { features: urlFeatures, signals: urlSignals } = settings.enableUrlAnalysis ? extractUrlFeatures(rawUrl) : { features: void 0, signals: [] };
  const typosquatResult = settings.enableTyposquatting ? analyzeTyposquatting(domain, settings.protectedBrands) : { signals: [], targetBrand: void 0, isLegitimateBrand: false };
  const pageTitle = formMetadata?.pageTitle || "";
  const visibleHeadings = socialMeta?.visibleHeadingsSample || [];
  const brandEval = evaluateBrandImpersonation(domain, pageTitle, visibleHeadings, formMetadata, socialMeta);
  const brandSignals = [];
  if (brandEval && !brandEval.isOfficial) {
    if (brandEval.isFreeHostingAbuse) {
      brandSignals.push({
        id: "SIGNAL_BRAND_FREE_HOSTING",
        category: "TYPOSQUATTING",
        type: "BRAND_IMPERSONATION_FREE_HOSTING",
        severity: "CRITICAL",
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
        id: "SIGNAL_BRAND_MISMATCH",
        category: "TYPOSQUATTING",
        type: "BRAND_DOMAIN_MISMATCH",
        severity: "HIGH",
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
  const formSignals = settings.enableDomAnalysis && formMetadata ? evaluateFormSecurity(rawUrl, formMetadata) : [];
  const socialSignals = settings.enableSocialEngineering && socialMeta ? evaluateSocialEngineering(socialMeta) : [];
  const downloadSignals = settings.enableDownloadContext && downloadContext ? evaluateDownloadContext(downloadContext) : [];
  const redirectSignals = settings.enableRedirectAnalysis && redirectData ? analyzeRedirectChain(redirectData) : [];
  const allSignals = [
    ...reputation.signals,
    ...urlSignals,
    ...typosquatResult.signals,
    ...brandSignals,
    ...formSignals,
    ...socialSignals,
    ...downloadSignals,
    ...redirectSignals
  ];
  const hasTyposquatOrHomoglyph = typosquatResult.signals.some(
    (s) => s.type === "HOMOGLYPH_SUBSTITUTION" || s.type === "TYPOSQUAT_DISTANCE_1" || s.type === "BRAND_COMBOSQUATTING"
  ) || brandSignals.length > 0;
  const hasCredentialField = formSignals.some(
    (s) => s.type === "CREDENTIAL_INPUT_FIELD" || s.type === "FINANCIAL_DATA_COLLECTION"
  ) || formMetadata?.hasPasswordInput || formMetadata?.hasCreditCardInput || formMetadata?.has2FAInput;
  const isIpAddress = urlSignals.some((s) => s.type === "IP_ADDRESS_HOSTNAME");
  const isCrossOriginHarvest = formSignals.some((s) => s.type === "CROSS_ORIGIN_CREDENTIAL_HARVESTER");
  const isSuspiciousTld = urlSignals.some((s) => s.type === "HIGH_RISK_TOP_LEVEL_DOMAIN");
  const hasSocialUrgency = socialSignals.some(
    (s) => s.type === "COERCIVE_URGENCY_WARNING" || s.type === "FAKE_TECH_SUPPORT_SCAM"
  );
  if (hasTyposquatOrHomoglyph && hasCredentialField) {
    allSignals.push({
      id: "SIGNAL_COMPOUND_TYPO_LOGIN",
      category: "TYPOSQUATTING",
      type: "COMPOUND_SPOOF_LOGIN_RISK",
      severity: "CRITICAL",
      weight: COMPOUND_PENALTY_TYPOSQUAT_LOGIN,
      title: "Active Credential Form on Lookalike / Impersonated Domain",
      description: "The webpage combines a brand lookalike or impersonated domain with an active authentication/verification form. This combination strongly correlates with phishing kit deployments.",
      confidence: 0.98
    });
  }
  if (isIpAddress && hasCredentialField) {
    allSignals.push({
      id: "SIGNAL_COMPOUND_IP_LOGIN",
      category: "DOM_SECURITY",
      type: "COMPOUND_IP_LOGIN_RISK",
      severity: "CRITICAL",
      weight: COMPOUND_PENALTY_IP_LOGIN,
      title: "Credential Entry Requested on Direct IP Hostname",
      description: "The website requests sensitive user authentication credentials while hosted on a bare IP address rather than a registered secure domain.",
      confidence: 0.97
    });
  }
  if (isCrossOriginHarvest && isSuspiciousTld) {
    allSignals.push({
      id: "SIGNAL_COMPOUND_CROSS_TLD",
      category: "DOM_SECURITY",
      type: "COMPOUND_CROSS_TLD_RISK",
      severity: "HIGH",
      weight: COMPOUND_PENALTY_CROSS_ORIGIN,
      title: "Cross-Origin Form on High-Risk TLD",
      description: "Form submission transfers data across domains on an unregistered/high-risk top-level domain.",
      confidence: 0.9
    });
  }
  if (hasSocialUrgency && hasCredentialField) {
    allSignals.push({
      id: "SIGNAL_COMPOUND_SOCENG_LOGIN",
      category: "SOCIAL_ENGINEERING",
      type: "COMPOUND_SOCENG_LOGIN_RISK",
      severity: "CRITICAL",
      weight: COMPOUND_PENALTY_SOCENG_LOGIN,
      title: "Coercive Urgency Combined with Credential Request",
      description: "The page combines coercive suspension/urgency language with sensitive login or credential inputs.",
      confidence: 0.95
    });
  }
  let baseScore = allSignals.reduce((sum, s) => sum + s.weight, 0);
  const isOfficialBrand = typosquatResult.isLegitimateBrand || brandEval && brandEval.isOfficial;
  if (isOfficialBrand) {
    baseScore = Math.round(baseScore * LEGITIMATE_BRAND_DAMPENER_FACTOR);
  }
  const multiplier = SENSITIVITY_MULTIPLIERS[settings.detectionSensitivity] || 1;
  const rawScore = Math.round(baseScore * multiplier);
  const score = Math.max(0, Math.min(100, rawScore));
  let severity = "SAFE";
  let verdict = "SAFE";
  if (score >= 80) {
    severity = "CRITICAL";
    verdict = "DANGEROUS";
  } else if (score >= 60) {
    severity = "HIGH";
    verdict = "HIGH_RISK";
  } else if (score >= 40) {
    severity = "MEDIUM";
    verdict = "SUSPICIOUS";
  } else if (score >= 20) {
    severity = "LOW";
    verdict = "LOW_RISK";
  } else {
    severity = "SAFE";
    verdict = "SAFE";
  }
  const evidenceItems = allSignals.map((sig) => ({
    id: sig.id,
    category: sig.category,
    severity: sig.severity,
    weight: sig.weight,
    summary: sig.title,
    explanation: sig.description
  }));
  const reasons = [];
  if (reputation.isBlocklisted) {
    reasons.push(`Domain is flagged on local threat blocklists (${reputation.matchedDomain}).`);
  }
  if (allSignals.length === 0) {
    reasons.push("No suspicious heuristics, typosquats, or deceptive form behaviors were detected.");
  } else {
    const topSignals = [...allSignals].sort((a, b) => b.weight - a.weight).slice(0, 4);
    for (const sig of topSignals) {
      reasons.push(sig.description);
    }
  }
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
export {
  analyzePageSecurity
};
