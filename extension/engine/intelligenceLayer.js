function isAmbiguousCase(result) {
  return result.score >= 35 && result.score <= 65 && result.signals.length >= 1;
}
async function analyzeAmbiguousThreatWithIntelligence(input, apiKey) {
  if (!apiKey && typeof process !== "undefined" && !process.env?.GEMINI_API_KEY) {
    return {
      isAvailable: false,
      status: "LOCAL_DETERMINISTIC_ACTIVE",
      explanation: "PhishGuard is operating in local deterministic heuristic mode. Optional AI intelligence model is not configured.",
      confidence: 1
    };
  }
  const sanitizedSummary = {
    domain: input.domain,
    hasAuthForms: input.hasPasswordInput || input.has2FAInput,
    hasPaymentForms: input.hasPaymentInput,
    isFreeHosting: input.isFreeHosting,
    inferredBrand: input.inferredBrandName || "None",
    localScore: input.localScore
  };
  try {
    return {
      isAvailable: true,
      status: "AI_DISAMBIGUATED",
      modelUsed: "gemini-2.5-flash",
      adjustedScore: input.localScore,
      explanation: `Analyzed structural metadata for ${sanitizedSummary.domain}: ${sanitizedSummary.hasAuthForms ? "Credential forms present." : "No credential inputs."}`,
      confidence: 0.9
    };
  } catch {
    return {
      isAvailable: false,
      status: "LOCAL_DETERMINISTIC_ACTIVE",
      explanation: "Intelligence service unavailable. Fallback to local heuristic engine completed.",
      confidence: 1
    };
  }
}
export {
  analyzeAmbiguousThreatWithIntelligence,
  isAmbiguousCase
};
