import { extractRegisteredDomain } from '../engine/brandIdentity.js';
import { isTrustedFederatedProvider } from '../config/trustedProviders.js';
function createNetworkSecurityEvent(obsOrTabId, pageUrlArg, requestUrlArg, methodArg, typeArg, hasActiveCredentialFormArg = false) {
  let tabId = 0;
  let frameId;
  let documentId;
  let pageUrl = "";
  let requestUrl = "";
  let method = "GET";
  let requestType = "fetch";
  let timestamp = Date.now();
  let hasActiveCredentialForm = false;
  if (typeof obsOrTabId === "number") {
    tabId = obsOrTabId;
    pageUrl = typeof pageUrlArg === "string" ? pageUrlArg : "";
    requestUrl = typeof requestUrlArg === "string" ? requestUrlArg : "";
    method = typeof methodArg === "string" ? methodArg.toUpperCase() : "GET";
    requestType = typeof typeArg === "string" ? typeArg : "fetch";
    hasActiveCredentialForm = !!hasActiveCredentialFormArg;
  } else if (obsOrTabId && typeof obsOrTabId === "object") {
    tabId = typeof obsOrTabId.tabId === "number" ? obsOrTabId.tabId : 0;
    frameId = obsOrTabId.frameId;
    documentId = obsOrTabId.documentId;
    pageUrl = typeof obsOrTabId.pageUrl === "string" ? obsOrTabId.pageUrl : "";
    requestUrl = typeof obsOrTabId.requestUrl === "string" ? obsOrTabId.requestUrl : "";
    method = typeof obsOrTabId.method === "string" ? obsOrTabId.method.toUpperCase() : "GET";
    requestType = typeof obsOrTabId.type === "string" ? obsOrTabId.type : "fetch";
    timestamp = obsOrTabId.timeStamp || Date.now();
    hasActiveCredentialForm = !!pageUrlArg;
  }
  if (!pageUrl || !requestUrl || tabId <= 0) {
    return null;
  }
  let pageHostname = "";
  let destHostname = "";
  let pageOrigin = "";
  try {
    const pageParsed = new URL(pageUrl.startsWith("http") ? pageUrl : "https://" + pageUrl);
    pageHostname = pageParsed.hostname.toLowerCase();
    pageOrigin = pageParsed.origin;
  } catch {
    pageHostname = pageUrl.toLowerCase();
    pageOrigin = pageUrl;
  }
  try {
    const destParsed = new URL(requestUrl.startsWith("http") ? requestUrl : "https://" + requestUrl);
    destHostname = destParsed.hostname.toLowerCase();
  } catch {
    destHostname = requestUrl.toLowerCase();
  }
  const pageRegDomain = extractRegisteredDomain(pageHostname);
  const destRegDomain = extractRegisteredDomain(destHostname);
  const isCrossOrigin = pageRegDomain !== destRegDomain && destHostname !== "" && pageHostname !== "";
  const { isTrusted: isTrustedFederated, provider } = isTrustedFederatedProvider(destHostname);
  const isPost = method === "POST";
  const sensitiveSubmissionPattern = isCrossOrigin && isPost && hasActiveCredentialForm && !isTrustedFederated;
  let severity = "SAFE";
  let eventType = "NETWORK_REQUEST_OBSERVED";
  let title = "Network Request Observed";
  let description = `${method} request to ${destHostname}`;
  if (isTrustedFederated) {
    severity = "SAFE";
    eventType = "NETWORK_REQUEST_OBSERVED";
    title = `Legitimate ${provider?.name || "Federated Service"} Request`;
    description = `Authorized communication with trusted provider (${destHostname}).`;
  } else if (sensitiveSubmissionPattern) {
    severity = "CRITICAL";
    eventType = "CREDENTIAL_SUBMISSION_PATTERN";
    title = "Cross-Origin Data Exfiltration Pattern";
    description = `Asynchronous ${method} request dispatched to external domain (${destHostname}) while credentials or sensitive inputs are present.`;
  } else if (isCrossOrigin && isPost) {
    severity = "MEDIUM";
    eventType = "CROSS_ORIGIN_REQUEST_OBSERVED";
    title = "Cross-Origin Form or Data Submission";
    description = `${method} submission directed to external domain (${destHostname}) differing from page origin (${pageHostname}).`;
  } else if (isCrossOrigin) {
    severity = "LOW";
    eventType = "CROSS_ORIGIN_REQUEST_OBSERVED";
    title = "Cross-Origin Communication";
    description = `Sub-resource request to ${destHostname}.`;
  }
  return {
    id: `net_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp,
    tabId,
    frameId,
    documentId,
    pageUrl,
    pageOrigin,
    type: eventType,
    severity,
    title,
    description,
    destinationHostname: destHostname,
    isSameOrigin: !isCrossOrigin,
    isCrossOrigin,
    method,
    destinationUrl: requestUrl,
    requestType,
    sensitiveSubmissionPattern,
    evidence: {
      method,
      destinationHostname: destHostname,
      pageHostname,
      isCrossOrigin,
      requestType,
      sensitiveSubmissionPattern,
      isTrustedFederated
    }
  };
}
export {
  createNetworkSecurityEvent
};
