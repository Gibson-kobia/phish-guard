const EXECUTABLE_EXTENSIONS = [
  "exe",
  "msi",
  "bat",
  "cmd",
  "scr",
  "vbs",
  "js",
  "jar",
  "apk",
  "iso",
  "img",
  "vhd",
  "hta",
  "ps1",
  "wsf",
  "com",
  "pif"
];
function createDownloadSecurityEvent(ctxOrTabId, originUrlArg, downloadUrlArg, filenameArg, originRiskScoreArg, downloadIdArg) {
  let tabId = 0;
  let downloadId = 0;
  let url = "";
  let filename = "";
  let originUrl = "";
  let originRiskScore = 0;
  if (typeof ctxOrTabId === "number") {
    tabId = ctxOrTabId;
    originUrl = typeof originUrlArg === "string" ? originUrlArg : "";
    url = typeof downloadUrlArg === "string" ? downloadUrlArg : "";
    filename = typeof filenameArg === "string" ? filenameArg : url.split("/").pop() || "download";
    originRiskScore = typeof originRiskScoreArg === "number" ? originRiskScoreArg : 0;
    downloadId = typeof downloadIdArg === "number" ? downloadIdArg : 0;
  } else if (ctxOrTabId && typeof ctxOrTabId === "object") {
    tabId = typeof ctxOrTabId.tabId === "number" ? ctxOrTabId.tabId : 0;
    downloadId = typeof ctxOrTabId.downloadId === "number" ? ctxOrTabId.downloadId : 0;
    url = typeof ctxOrTabId.url === "string" ? ctxOrTabId.url : "";
    filename = typeof ctxOrTabId.filename === "string" ? ctxOrTabId.filename : url.split("/").pop() || "download";
    originUrl = typeof ctxOrTabId.originUrl === "string" ? ctxOrTabId.originUrl : "";
    originRiskScore = typeof ctxOrTabId.originRiskScore === "number" ? ctxOrTabId.originRiskScore : 0;
  }
  const safeFilename = filename || "download";
  const parts = safeFilename.split(".");
  const ext = parts.length > 1 ? (parts[parts.length - 1] || "").toLowerCase() : "";
  const isExecutable = EXECUTABLE_EXTENSIONS.includes(ext);
  let originOrigin = "";
  try {
    originOrigin = new URL(originUrl.startsWith("http") ? originUrl : "https://" + originUrl).origin;
  } catch {
    originOrigin = originUrl;
  }
  let severity = "LOW";
  let title = "File Download Triggered";
  let description = `Download initiated for ${safeFilename}.`;
  if (isExecutable && originRiskScore >= 60) {
    severity = "CRITICAL";
    title = "Dangerous Executable Download on High-Risk Site";
    description = `An executable file (${safeFilename}) was triggered from a high-risk or suspicious webpage (Risk: ${originRiskScore}/100).`;
  } else if (isExecutable) {
    severity = "MEDIUM";
    title = "Executable File Download";
    description = `Binary executable (${safeFilename}) download initiated.`;
  }
  return {
    id: `dl_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId,
    pageUrl: originUrl,
    pageOrigin: originOrigin,
    type: "DOWNLOAD_TRIGGERED",
    severity,
    title,
    description,
    downloadId,
    filename: safeFilename,
    fileExtension: ext,
    downloadUrl: url,
    isExecutable,
    originRiskScore,
    evidence: {
      filename: safeFilename,
      fileExtension: ext,
      isExecutable,
      originRiskScore
    }
  };
}
export {
  EXECUTABLE_EXTENSIONS,
  createDownloadSecurityEvent
};
