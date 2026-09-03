import { SUSPICIOUS_KEYWORDS, HIGH_RISK_TLDS, SUSPICIOUS_PORTS } from '../config/rules.js';
function extractUrlFeatures(rawUrl) {
  const signals = [];
  let cleanUrl = rawUrl.trim();
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://") && !cleanUrl.startsWith("ftp://")) {
    cleanUrl = "https://" + cleanUrl;
  }
  let parsed;
  try {
    parsed = new URL(cleanUrl);
  } catch {
    try {
      parsed = new URL("https://" + cleanUrl.replace(/^https?:\/\//, ""));
    } catch {
      parsed = new URL("https://invalid-url-format.local");
    }
  }
  const protocol = parsed.protocol.replace(":", "").toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const path = parsed.pathname;
  const query = parsed.search;
  const port = parsed.port;
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^\[?([a-f0-9:]+)\]?$/i;
  const hexIpPattern = /^0x[0-9a-f]+$/i;
  const intIpPattern = /^\d{8,12}$/;
  const isIpv4 = ipv4Pattern.test(hostname);
  const isIpv6 = ipv6Pattern.test(hostname);
  const isHexOrInt = hexIpPattern.test(hostname) || intIpPattern.test(hostname);
  const isIpAddress = isIpv4 || isIpv6 || isHexOrInt;
  if (isIpAddress && hostname !== "127.0.0.1" && hostname !== "localhost" && hostname !== "::1") {
    signals.push({
      id: "SIGNAL_IP_HOST",
      category: "URL_STRUCTURE",
      type: "IP_ADDRESS_HOSTNAME",
      severity: "HIGH",
      weight: 45,
      title: "IP Address Used as Hostname",
      description: `Website uses a direct IP address (${hostname}) instead of a standard registered domain name. Legitimate web services rarely use raw IP addresses for user-facing web pages.`,
      confidence: 0.95,
      evidence: { hostname }
    });
  }
  const isPunycode = hostname.startsWith("xn--") || hostname.includes(".xn--");
  let decodedPunycode;
  if (isPunycode) {
    decodedPunycode = hostname.split(".").map((part) => part.startsWith("xn--") ? `[Unicode:${part.substring(4)}]` : part).join(".");
    signals.push({
      id: "SIGNAL_PUNYCODE_IDN",
      category: "URL_STRUCTURE",
      type: "IDN_PUNYCODE_DETECTED",
      severity: "HIGH",
      weight: 35,
      title: "Internationalized Domain Name (Punycode / IDN)",
      description: `Domain contains Punycode encoded characters (${hostname}). Attackers frequently use IDN characters to craft visual lookalikes of popular domains.`,
      confidence: 0.9,
      evidence: { hostname, decodedPunycode }
    });
  }
  const hasNonAsciiInHost = /[^\u0000-\u007F]/.test(hostname);
  if (hasNonAsciiInHost) {
    signals.push({
      id: "SIGNAL_NON_ASCII_DOMAIN",
      category: "URL_STRUCTURE",
      type: "NON_ASCII_HOST_CHARS",
      severity: "HIGH",
      weight: 40,
      title: "Non-ASCII Characters in Hostname",
      description: "Hostname contains raw Unicode characters outside standard ASCII, which is a common homograph attack technique.",
      confidence: 0.95,
      evidence: { hostname }
    });
  }
  const domainParts = hostname.split(".").filter(Boolean);
  let effectiveDomain = hostname;
  let subdomainCount = 0;
  const twoPartTlds = ["co.uk", "com.au", "co.nz", "co.jp", "com.br", "co.za", "gov.uk", "edu.au", "com.sg", "co.il"];
  const hasTwoPartTld = twoPartTlds.some((t) => hostname.endsWith("." + t));
  if (domainParts.length >= 2) {
    if (hasTwoPartTld && domainParts.length >= 3) {
      effectiveDomain = domainParts.slice(-3).join(".");
      subdomainCount = domainParts.length - 3;
    } else {
      effectiveDomain = domainParts.slice(-2).join(".");
      subdomainCount = domainParts.length - 2;
    }
  }
  const tld = domainParts.length > 0 ? domainParts[domainParts.length - 1] : "";
  if (subdomainCount >= 3) {
    const depthPenalty = Math.min(20, (subdomainCount - 2) * 8);
    signals.push({
      id: "SIGNAL_EXCESSIVE_SUBDOMAINS",
      category: "URL_STRUCTURE",
      type: "EXCESSIVE_SUBDOMAINS",
      severity: subdomainCount >= 4 ? "HIGH" : "MEDIUM",
      weight: 20 + depthPenalty,
      title: `Excessive Subdomain Depth (${subdomainCount} subdomains)`,
      description: `Hostname contains ${subdomainCount} subdomains. Phishing sites frequently stack multiple subdomains (e.g. login.paypal.com.attacker.xyz) to deceive mobile users.`,
      confidence: 0.85,
      evidence: { subdomainCount, effectiveDomain, fullHost: hostname }
    });
  }
  const hasUserinfo = Boolean(parsed.username || parsed.password) || rawUrl.includes("@") && (() => {
    try {
      const withoutProto = rawUrl.replace(/^[a-zA-Z]+:\/\//, "");
      const authority = withoutProto.split("/")[0].split("?")[0].split("#")[0];
      return authority.includes("@");
    } catch {
      return false;
    }
  })();
  if (hasUserinfo) {
    signals.push({
      id: "SIGNAL_USERINFO_SPOOF",
      category: "URL_STRUCTURE",
      type: "USERINFO_AUTHENTICATION_SPOOF",
      severity: "CRITICAL",
      weight: 60,
      title: 'Deceptive User Authentication "@" Spoof',
      description: 'URL contains an "@" symbol in the authority segment. Browsers treat preceding text as user credentials and navigate to the domain after the "@", disguising the actual destination.',
      confidence: 0.98,
      evidence: { rawUrl }
    });
  }
  const hasSuspiciousPort = port !== "" && SUSPICIOUS_PORTS.includes(port);
  if (hasSuspiciousPort) {
    signals.push({
      id: "SIGNAL_SUSPICIOUS_PORT",
      category: "URL_STRUCTURE",
      type: "SUSPICIOUS_NON_STANDARD_PORT",
      severity: "MEDIUM",
      weight: 22,
      title: `Non-Standard Network Port (:${port})`,
      description: `Website runs on port ${port} instead of standard HTTP (80) or HTTPS (443). Phishing kits frequently host payloads on non-standard ports to evade enterprise filters.`,
      confidence: 0.8,
      evidence: { port }
    });
  }
  if (protocol === "http" && hostname !== "localhost" && hostname !== "127.0.0.1") {
    signals.push({
      id: "SIGNAL_INSECURE_HTTP",
      category: "URL_STRUCTURE",
      type: "UNENCRYPTED_HTTP_PROTOCOL",
      severity: "LOW",
      weight: 15,
      title: "Unencrypted HTTP Connection",
      description: "Website does not enforce TLS encryption (HTTPS). Any login credentials or personal data entered can be intercepted in transit.",
      confidence: 0.9,
      evidence: { protocol }
    });
  }
  const hasHighRiskTld = HIGH_RISK_TLDS.includes(tld);
  if (hasHighRiskTld) {
    signals.push({
      id: "SIGNAL_HIGH_RISK_TLD",
      category: "URL_STRUCTURE",
      type: "HIGH_RISK_TOP_LEVEL_DOMAIN",
      severity: "LOW",
      weight: 12,
      title: `High-Risk Top Level Domain (.${tld})`,
      description: `Domain uses .${tld}, a TLD statistically associated with high volumes of automated spam and disposable phishing campaigns.`,
      confidence: 0.7,
      evidence: { tld }
    });
  }
  const searchCorpus = (hostname + path + query).toLowerCase();
  const matchedKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORDS) {
    if (searchCorpus.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }
  if (matchedKeywords.length >= 2) {
    const isMainDomainKeyword = domainParts.length >= 2 && matchedKeywords.includes(domainParts[domainParts.length - 2]);
    const weight = isMainDomainKeyword ? 18 : 28;
    signals.push({
      id: "SIGNAL_SUSPICIOUS_KEYWORDS",
      category: "URL_STRUCTURE",
      type: "SECURITY_KEYWORDS_DENSITY",
      severity: matchedKeywords.length >= 3 ? "MEDIUM" : "LOW",
      weight,
      title: `High Security Keyword Density (${matchedKeywords.length} terms)`,
      description: `URL contains urgent security-themed terms: [${matchedKeywords.slice(0, 4).join(", ")}]. Phishing URLs frequently pack terms like "verify", "secure", and "account" to mimic official portals.`,
      confidence: 0.75,
      evidence: { matchedKeywords }
    });
  }
  const hyphenCount = (hostname.match(/-/g) || []).length;
  const dotCount = (hostname.match(/\./g) || []).length;
  if (rawUrl.length > 120) {
    signals.push({
      id: "SIGNAL_EXCESSIVE_URL_LENGTH",
      category: "URL_STRUCTURE",
      type: "ANOMALOUS_URL_LENGTH",
      severity: "LOW",
      weight: 10,
      title: `Excessive URL Length (${rawUrl.length} chars)`,
      description: "The overall URL is unusually long, which is often used in obfuscated phishing links to push the actual host off mobile address bars.",
      confidence: 0.65,
      evidence: { length: rawUrl.length }
    });
  }
  if (hyphenCount >= 3) {
    signals.push({
      id: "SIGNAL_EXCESSIVE_HYPHENS",
      category: "URL_STRUCTURE",
      type: "EXCESSIVE_HYPHENATION",
      severity: "LOW",
      weight: 14,
      title: `Excessive Domain Hyphenation (${hyphenCount} hyphens)`,
      description: "Domain uses multiple hyphens to chain brand names with deceptive security words (e.g. paypal-security-update-center).",
      confidence: 0.75,
      evidence: { hyphenCount }
    });
  }
  const entropy = calculateEntropy(hostname);
  if (entropy > 4.1 && hostname.length > 16 && !isIpAddress) {
    signals.push({
      id: "SIGNAL_HIGH_ENTROPY_HOST",
      category: "URL_STRUCTURE",
      type: "RANDOMIZED_DGA_HOSTNAME",
      severity: "MEDIUM",
      weight: 24,
      title: "High Character Entropy (Randomized Hostname)",
      description: "Hostname has an unusually high degree of randomness, characteristic of Domain Generation Algorithms (DGAs) used by automated botnets and phishing infrastructure.",
      confidence: 0.8,
      evidence: { entropy: entropy.toFixed(2) }
    });
  }
  const features = {
    protocol,
    hostname,
    path,
    query,
    port,
    isIpAddress,
    isPunycode,
    decodedPunycode,
    subdomainCount,
    domainParts,
    tld,
    hasUserinfo,
    hasSuspiciousPort,
    hasHighRiskTld,
    suspiciousKeywords: matchedKeywords,
    length: rawUrl.length,
    entropy,
    hyphenCount,
    dotCount
  };
  return { features, signals };
}
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
export {
  extractUrlFeatures
};
