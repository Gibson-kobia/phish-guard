import { DEFAULT_ALLOWLIST, DEMO_KNOWN_MALICIOUS_DOMAINS } from '../config/brands.js';
function checkDomainReputation(domain, customAllowlist, customBlocklist) {
  const allowlist = customAllowlist || DEFAULT_ALLOWLIST;
  const blocklist = customBlocklist || DEMO_KNOWN_MALICIOUS_DOMAINS;
  const cleanDomain = domain.toLowerCase().trim();
  const signals = [];
  for (const allowed of allowlist) {
    const cleanAllowed = allowed.toLowerCase().trim();
    if (cleanDomain === cleanAllowed || cleanDomain.endsWith("." + cleanAllowed)) {
      return {
        isAllowlisted: true,
        isBlocklisted: false,
        matchedDomain: cleanAllowed,
        signals: []
      };
    }
  }
  for (const blocked of blocklist) {
    const cleanBlocked = blocked.toLowerCase().trim();
    if (cleanDomain === cleanBlocked || cleanDomain.endsWith("." + cleanBlocked)) {
      signals.push({
        id: "SIGNAL_KNOWN_MALICIOUS_REPUTATION",
        category: "REPUTATION",
        type: "KNOWN_THREAT_DATABASE_HIT",
        severity: "CRITICAL",
        weight: 95,
        title: "Known Threat / Phishing Database Match",
        description: `Domain (${cleanDomain}) matches an active malicious entry in the local threat intelligence blocklist (${cleanBlocked}).`,
        confidence: 0.99,
        evidence: {
          matchedEntry: cleanBlocked,
          domain: cleanDomain
        }
      });
      return {
        isAllowlisted: false,
        isBlocklisted: true,
        matchedDomain: cleanBlocked,
        signals
      };
    }
  }
  return {
    isAllowlisted: false,
    isBlocklisted: false,
    signals: []
  };
}
export {
  checkDomainReputation
};
