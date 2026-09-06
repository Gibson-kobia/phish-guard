const EXECUTABLE_EXTENSIONS = /* @__PURE__ */ new Set([
  "exe",
  "msi",
  "scr",
  "bat",
  "cmd",
  "vbs",
  "ps1",
  "iso",
  "img",
  "jar",
  "apk",
  "dmg",
  "pkg"
]);
function evaluateDownloadContext(context) {
  const signals = [];
  if (!context) return signals;
  const ext = (context.fileExtension || "").toLowerCase().replace(/^\./, "");
  const isExec = EXECUTABLE_EXTENSIONS.has(ext);
  if (context.originRiskScore >= 70 || context.isDangerousOrigin) {
    signals.push({
      id: "SIGNAL_DOWNLOAD_DANGEROUS_ORIGIN",
      category: "DOWNLOAD_SECURITY",
      type: "DOWNLOAD_FROM_HIGH_RISK_PAGE",
      severity: "CRITICAL",
      weight: 35,
      title: "Download Initiated from High-Risk Website",
      description: `The file "${context.filename}" was initiated from a website evaluated as high-risk (${context.originRiskScore}/100). PhishGuard warns against opening untrusted files from lookalike origins.`,
      evidence: {
        filename: context.filename,
        originRisk: context.originRiskScore,
        originUrl: context.originUrl
      },
      confidence: 0.95
    });
  } else if (context.originRiskScore >= 40) {
    signals.push({
      id: "SIGNAL_DOWNLOAD_SUSPICIOUS_ORIGIN",
      category: "DOWNLOAD_SECURITY",
      type: "DOWNLOAD_FROM_SUSPICIOUS_PAGE",
      severity: "HIGH",
      weight: 20,
      title: "Download Initiated from Suspicious Origin",
      description: `The download "${context.filename}" originates from a page with suspicious security signals.`,
      evidence: {
        filename: context.filename,
        originRisk: context.originRiskScore
      },
      confidence: 0.85
    });
  }
  if (isExec && context.originRiskScore >= 30) {
    signals.push({
      id: "SIGNAL_DOWNLOAD_EXECUTABLE_UNTRUSTED",
      category: "DOWNLOAD_SECURITY",
      type: "EXECUTABLE_DOWNLOAD_UNTRUSTED_SOURCE",
      severity: "HIGH",
      weight: 25,
      title: "Executable File Download from Untrusted Source",
      description: `The file "${context.filename}" is an executable format (.${ext}) triggered from an unverified domain.`,
      evidence: {
        filename: context.filename,
        extension: ext
      },
      confidence: 0.9
    });
  }
  return signals;
}
export {
  evaluateDownloadContext
};
