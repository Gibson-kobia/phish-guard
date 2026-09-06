function sanitizeUrlForReporting(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    let path = parsed.pathname;
    if (path.length > 120) {
      path = path.slice(0, 120) + "...";
    }
    const sanitizedUrl = `${parsed.protocol}//${hostname}${path}`;
    return { sanitizedUrl, hostname };
  } catch {
    const clean = rawUrl.split("?")[0].split("#")[0].slice(0, 100);
    return { sanitizedUrl: clean, hostname: "unknown" };
  }
}
function mapToEnterpriseRiskLevel(score, verdict) {
  if (score >= 80 || verdict === "DANGEROUS") return "CRITICAL";
  if (score >= 60 || verdict === "HIGH_RISK") return "HIGH";
  if (score >= 35 || verdict === "SUSPICIOUS") return "MEDIUM";
  if (score >= 15 || verdict === "LOW_RISK") return "LOW";
  return "SAFE";
}
function inferPrimaryThreatCategory(analysis) {
  if (analysis.targetBrand) return "BRAND_IMPERSONATION";
  const signals = analysis.signals || [];
  for (const s of signals) {
    if (s.type.includes("BRAND_IMPERSONATION") || s.type.includes("FREE_HOSTING")) return "BRAND_IMPERSONATION";
    if (s.category === "TYPOSQUATTING" || s.type.includes("TYPO")) return "TYPOSQUAT_CAMPAIGN";
    if (s.type.includes("2FA")) return "2FA_INTERCEPTION";
    if (s.type.includes("CREDENTIAL") || s.type.includes("PASSWORD")) return "CREDENTIAL_HARVESTING";
    if (s.type.includes("PAYMENT") || s.type.includes("CREDIT_CARD")) return "PAYMENT_FRAUD";
    if (s.type.includes("SCAREWARE") || s.category === "SOCIAL_ENGINEERING") return "SCAREWARE_TECH_SUPPORT";
    if (s.category === "REDIRECT_CHAIN" || s.category === "REDIRECT") return "REDIRECT_SMUGGLING";
    if (s.category === "DOWNLOAD_SECURITY") return "MALWARE_DROPPER";
  }
  if (analysis.score >= 80) return "BRAND_IMPERSONATION";
  if (analysis.score >= 60) return "CREDENTIAL_HARVESTING";
  if (analysis.score >= 40) return "TYPOSQUAT_CAMPAIGN";
  return "OTHER";
}
function buildCanonicalSecurityEvent(options) {
  const { sanitizedUrl, hostname } = sanitizeUrlForReporting(options.url);
  const now = options.analysis.timestamp || Date.now();
  const eventId = `evt_${now}_${Math.random().toString(36).slice(2, 8)}`;
  const riskLevel = mapToEnterpriseRiskLevel(options.analysis.score, options.analysis.verdict);
  const threatCategory = inferPrimaryThreatCategory(options.analysis);
  const isBlocked = options.action === "BLOCKED" || options.analysis.score >= 80 && options.action !== "ALLOWED" && options.action !== "USER_OVERRIDE";
  const action = options.action || (isBlocked ? "BLOCKED" : options.analysis.score >= 40 ? "WARNED" : "ALLOWED");
  const eventType = options.eventType || (isBlocked ? "NAVIGATION_BLOCKED" : options.analysis.score >= 40 ? "WARNING_DISPLAYED" : "SAFE_VISIT");
  const formattedSignals = (options.analysis.signals || []).map((s) => ({
    id: s.id,
    category: s.category,
    type: s.type,
    severity: s.severity,
    weight: s.weight,
    title: s.title,
    description: s.description,
    confidence: s.confidence
  }));
  return {
    eventId,
    timestamp: now,
    tabId: options.tabId || 0,
    deviceId: options.deviceId || "DEV-UNASSIGNED",
    installationId: options.installationId || "inst-local-unregistered",
    organizationId: options.organizationId || "ORG-DEFAULT",
    extensionVersion: options.extensionVersion || "1.0.0",
    browserVersion: options.browserVersion || "Chrome MV3",
    os: options.os || "Unknown OS",
    eventType,
    url: sanitizedUrl,
    hostname,
    riskScore: Math.round(options.analysis.score),
    riskLevel,
    action,
    detectionReasons: options.analysis.reasons || [],
    signals: formattedSignals,
    brand: options.analysis.targetBrand?.name || null,
    threatCategory,
    navigationBlocked: isBlocked,
    userOverride: options.userOverride || false,
    source: "CLIENT_EXTENSION",
    createdAt: new Date(now).toISOString()
  };
}
export {
  buildCanonicalSecurityEvent,
  inferPrimaryThreatCategory,
  mapToEnterpriseRiskLevel,
  sanitizeUrlForReporting
};
