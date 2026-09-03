/**
 * PhishGuard Behavioral Detection Test Suite
 * 
 * Contains deterministic local test fixtures representing 18 distinct
 * realistic phishing, generic identity mismatch, and legitimate browsing scenarios.
 * 
 * STRICT TEST SAFETY:
 * Does NOT contact real malicious infrastructure.
 * Does NOT use real user credentials.
 */

import { SecurityTestCase, SecurityAnalysisResult, Verdict } from '../types';
import { analyzePageSecurity } from '../engine/riskScoring';

export const SECURITY_TEST_CASES: SecurityTestCase[] = [
  // Scenario 1: Brand impersonation on unrelated hosting (Vinted on Netlify)
  {
    id: 'scenario_1_vinted_netlify',
    name: '1. Brand Impersonation on Unrelated Hosting (Vinted on Netlify)',
    description: 'Deceptive marketplace site using Vinted branding hosted on Netlify free subdomain with credential form.',
    category: 'COMBOSQUAT',
    url: 'https://vintedmarket.netlify.app/login/verify-account',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: true,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://vintedmarket.netlify.app/api/auth',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 3,
        hiddenInputsCount: 1
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Vinted UK - Login & Verification'
    },
    expectedVerdict: 'DANGEROUS',
    expectedMinScore: 80,
    expectedMaxScore: 100,
    expectedSignals: ['BRAND_IMPERSONATION_FREE_HOSTING']
  },

  // Scenario 2: Typosquatting (paypa1.com)
  {
    id: 'scenario_2_typosquatting_paypal',
    name: '2. Typosquatting (paypa1.com)',
    description: 'Digit substitution (1 -> l) spoofing PayPal with active password form.',
    category: 'HOMOGLYPH',
    url: 'https://www.paypa1.com/signin/account-verify',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://www.paypa1.com/submit',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 2,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 70,
    expectedMaxScore: 100,
    expectedSignals: ['HOMOGLYPH_SUBSTITUTION']
  },

  // Scenario 3: Homoglyph domain (amaz0n-login.top)
  {
    id: 'scenario_3_homoglyph_amazon',
    name: '3. Homoglyph Domain (amaz0n-security-alert.top)',
    description: 'Digit 0 substitution spoofing Amazon with high-risk TLD.',
    category: 'HOMOGLYPH',
    url: 'https://amaz0n-security-alert.top/account/recover',
    mockForm: null,
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 60,
    expectedMaxScore: 100,
    expectedSignals: ['HOMOGLYPH_SUBSTITUTION', 'HIGH_RISK_TOP_LEVEL_DOMAIN']
  },

  // Scenario 4: Punycode IDN
  {
    id: 'scenario_4_punycode_apple',
    name: '4. Punycode IDN (xn--pple-43d.com)',
    description: 'Punycode encoded internationalized domain name mimicking apple.com.',
    category: 'HOMOGLYPH',
    url: 'https://xn--pple-43d.com/support/apple-id',
    mockForm: null,
    expectedVerdict: 'SUSPICIOUS',
    expectedMinScore: 40,
    expectedMaxScore: 75,
    expectedSignals: ['IDN_PUNYCODE_DETECTED']
  },

  // Scenario 5: Credential Harvesting on Insecure Origin
  {
    id: 'scenario_5_credential_harvesting_ip',
    name: '5. Credential Harvesting (Raw IP & Insecure HTTP)',
    description: 'Unencrypted HTTP credential form hosted directly on a public IPv4 address.',
    category: 'RAW_IP',
    url: 'http://185.220.101.5/login.php',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'http://185.220.101.5/login.php',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: true,
        hasPasswordField: true,
        inputCount: 2,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 70,
    expectedMaxScore: 100,
    expectedSignals: ['IP_ADDRESS_HOSTNAME', 'COMPOUND_IP_LOGIN_RISK']
  },

  // Scenario 6: Payment Form Harvesting
  {
    id: 'scenario_6_payment_harvesting',
    name: '6. Payment Form Harvesting (netf1ix-billing-update.xyz)',
    description: 'Fake billing update asking for credit card numbers on high-risk TLD.',
    category: 'HOMOGLYPH',
    url: 'https://netf1ix-billing-update.xyz/login/verify-card',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: true,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://netf1ix-billing-update.xyz/capture',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 6,
        hiddenInputsCount: 1
      }],
      hasHiddenCredentialFields: false
    },
    expectedVerdict: 'DANGEROUS',
    expectedMinScore: 80,
    expectedMaxScore: 100,
    expectedSignals: ['FINANCIAL_DATA_COLLECTION', 'HIGH_RISK_TOP_LEVEL_DOMAIN']
  },

  // Scenario 7: Verification-Code (2FA/OTP) Harvesting
  {
    id: 'scenario_7_verification_code_harvesting',
    name: '7. Verification-Code Harvesting (2FA Interceptor)',
    description: 'Phishing portal prompting for SMS / authenticator one-time passcode on spoofed domain.',
    category: 'COMBOSQUAT',
    url: 'https://secure-chase-verification-portal.click/2fa',
    mockForm: {
      hasPasswordInput: false,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: false,
      has2FAInput: true,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://secure-chase-verification-portal.click/verify',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: false,
        inputCount: 2,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Chase Online Security Verification'
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 60,
    expectedMaxScore: 100,
    expectedSignals: ['BRAND_DOMAIN_MISMATCH']
  },

  // Scenario 8: Cross-Origin Credential Submission
  {
    id: 'scenario_8_cross_origin_submission',
    name: '8. Cross-Origin Credential Submission',
    description: 'Login form that submits entered credentials to an external drop server.',
    category: 'CREDENTIAL_HARVEST',
    url: 'https://company-intranet-portal.com/login',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://stolen-data-drop-collector.xyz/steal.php',
        method: 'POST',
        isCrossOrigin: true,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 3,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 65,
    expectedMaxScore: 100,
    expectedSignals: ['CROSS_ORIGIN_CREDENTIAL_HARVESTER']
  },

  // Scenario 9: Suspicious API Destination / Scareware Tech Support
  {
    id: 'scenario_9_scareware_alert',
    name: '9. Suspicious Scareware Alert',
    description: 'Deceptive fake system lockdown / scareware message.',
    category: 'SOCIAL_ENGINEERING',
    url: 'https://windows-defender-security-alert-call.top/help',
    mockSocial: {
      hasUrgencyLanguage: true,
      hasAccountSuspensionNotice: false,
      hasCredentialVerificationPrompt: false,
      hasFakeTechSupportLanguage: true,
      hasPaymentUrgency: false,
      hasPrizeOrRewardClaim: false,
      detectedPhrases: ['Impersonated system security alert', 'Fake toll-free tech support prompt'],
      visibleHeadingsSample: ['Windows Defender Alert: Trojan Detected! Call +1-800-000-0000']
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 60,
    expectedMaxScore: 100,
    expectedSignals: ['FAKE_TECH_SUPPORT_SCAM']
  },

  // Scenario 10: Redirect Chain via URL Shortener
  {
    id: 'scenario_10_redirect_chain',
    name: '10. Redirect Chain (Shortener Trampoline)',
    description: 'Multi-hop redirect traversing URL shorteners to obscure the landing origin.',
    category: 'REDIRECT',
    url: 'https://final-suspicious-landing-page.com',
    mockForm: null,
    mockRedirect: {
      initialUrl: 'https://bit.ly/3xSpecialLogin',
      finalUrl: 'https://final-suspicious-landing-page.com',
      hops: [
        { url: 'https://bit.ly/3xSpecialLogin', timestamp: 1000 },
        { url: 'https://tld-tracker-bounce.net/click?id=12', timestamp: 1200 },
        { url: 'https://final-suspicious-landing-page.com', timestamp: 1400 }
      ],
      hopCount: 3,
      hasUrlShortener: true
    },
    expectedVerdict: 'SUSPICIOUS',
    expectedMinScore: 40,
    expectedMaxScore: 75,
    expectedSignals: ['MULTI_HOP_REDIRECT_CHAIN']
  },

  // Scenario 11: Executable Download Attempt from High-Risk Site
  {
    id: 'scenario_11_download_high_risk',
    name: '11. Download Attempt from High-Risk Origin',
    description: 'Executable payload (.msi/.exe) downloaded from an untrusted origin.',
    category: 'DOWNLOAD_CONTEXT',
    url: 'https://micros0ft-office-update.xyz/download',
    mockDownload: {
      downloadId: 42,
      url: 'https://micros0ft-office-update.xyz/files/OfficeSetup.msi',
      filename: 'OfficeSetup.msi',
      fileExtension: 'msi',
      originUrl: 'https://micros0ft-office-update.xyz/download',
      originRiskScore: 82,
      originVerdict: 'HIGH_RISK',
      isDangerousOrigin: true,
      isExecutable: true,
      timestamp: Date.now()
    },
    expectedVerdict: 'DANGEROUS',
    expectedMinScore: 80,
    expectedMaxScore: 100,
    expectedSignals: ['DOWNLOAD_FROM_HIGH_RISK_PAGE']
  },

  // Scenario 12: Legitimate Branded Site (Official Vinted)
  {
    id: 'scenario_12_legitimate_vinted',
    name: '12. Legitimate Branded Site (Official Vinted)',
    description: 'Official Vinted marketplace with password login and same-origin form.',
    category: 'SAFE_BASELINE',
    url: 'https://www.vinted.com/member/general/login',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://www.vinted.com/api/v2/users/session',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 2,
        hiddenInputsCount: 1
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Vinted - Buy and sell secondhand fashion'
    },
    expectedVerdict: 'SAFE',
    expectedMinScore: 0,
    expectedMaxScore: 19,
    expectedSignals: []
  },

  // Scenario 13: Legitimate SaaS Login (GitHub)
  {
    id: 'scenario_13_legitimate_github',
    name: '13. Legitimate SaaS Login (GitHub)',
    description: 'Official GitHub login page with authentic authentication actions.',
    category: 'SAFE_BASELINE',
    url: 'https://github.com/login',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://github.com/session',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 3,
        hiddenInputsCount: 2
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Sign in to GitHub · GitHub'
    },
    expectedVerdict: 'SAFE',
    expectedMinScore: 0,
    expectedMaxScore: 19,
    expectedSignals: []
  },

  // Scenario 14: Legitimate Payment Provider (Stripe Checkout)
  {
    id: 'scenario_14_legitimate_stripe',
    name: '14. Legitimate Payment Provider (Stripe Checkout)',
    description: 'Official Stripe Checkout portal with card fields on canonical domain.',
    category: 'SAFE_BASELINE',
    url: 'https://checkout.stripe.com/c/pay/cs_live_sample',
    mockForm: {
      hasPasswordInput: false,
      hasCreditCardInput: true,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://checkout.stripe.com/api/confirm',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: false,
        inputCount: 4,
        hiddenInputsCount: 2
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Stripe Checkout'
    },
    expectedVerdict: 'SAFE',
    expectedMinScore: 0,
    expectedMaxScore: 19,
    expectedSignals: []
  },

  // Scenario 15: False-Positive Baseline (Documentation Subdomain & Email in Query)
  {
    id: 'scenario_15_false_positive_baseline',
    name: '15. False-Positive Baseline (Docs & Newsletter Signup)',
    description: 'Legitimate developer documentation with deep subdomains and email query parameter.',
    category: 'SAFE_BASELINE',
    url: 'https://developer.chrome.com/docs/extensions/mv3/intro?subscriber=user@example.com',
    mockForm: null,
    expectedVerdict: 'SAFE',
    expectedMinScore: 0,
    expectedMaxScore: 19,
    expectedSignals: []
  },

  // Scenario 16: Generic Brand Impersonation on Vercel (Jumia on Vercel)
  {
    id: 'scenario_16_jumia_vercel',
    name: '16. Generic Brand Impersonation (Jumia on Vercel)',
    description: 'Jumia shopping portal impersonated on Vercel with login form.',
    category: 'COMBOSQUAT',
    url: 'https://jumia.vercel.app/customer/account/login',
    mockForm: {
      hasPasswordInput: true,
      hasCreditCardInput: false,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://jumia.vercel.app/api/auth',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: true,
        inputCount: 2,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Jumia Online Shopping - Account Login'
    },
    expectedVerdict: 'DANGEROUS',
    expectedMinScore: 80,
    expectedMaxScore: 100,
    expectedSignals: ['BRAND_IMPERSONATION_FREE_HOSTING']
  },

  // Scenario 17: Unverified Payment on Free Subdomain
  {
    id: 'scenario_17_payment_free_hosting',
    name: '17. Payment Form on Free Subdomain (random-shop.vercel.app)',
    description: 'Generic storefront collecting credit card numbers on Vercel free hosting.',
    category: 'COMBOSQUAT',
    url: 'https://random-shop.vercel.app/checkout',
    mockForm: {
      hasPasswordInput: false,
      hasCreditCardInput: true,
      hasSsnInput: false,
      hasEmailOrUserInput: true,
      has2FAInput: false,
      formsCount: 1,
      suspiciousForms: [{
        action: 'https://random-shop.vercel.app/process',
        method: 'POST',
        isCrossOrigin: false,
        isInsecureHttp: false,
        hasPasswordField: false,
        inputCount: 4,
        hiddenInputsCount: 0
      }],
      hasHiddenCredentialFields: false,
      pageTitle: 'Checkout - Complete Your Order'
    },
    expectedVerdict: 'HIGH_RISK',
    expectedMinScore: 60,
    expectedMaxScore: 100,
    expectedSignals: ['FINANCIAL_DATA_COLLECTION']
  },

  // Scenario 18: Clean Personal Website on Netlify (No Forms)
  {
    id: 'scenario_18_clean_netlify_portfolio',
    name: '18. Clean Personal Portfolio on Netlify',
    description: 'Ordinary static developer website on Netlify without any authentication or payment inputs.',
    category: 'SAFE_BASELINE',
    url: 'https://my-developer-portfolio.netlify.app/about',
    mockForm: null,
    expectedVerdict: 'SAFE',
    expectedMinScore: 0,
    expectedMaxScore: 19,
    expectedSignals: []
  }
];

export interface TestRunResult {
  id: string;
  testName: string;
  category: string;
  description: string;
  passed: boolean;
  actualVerdict: Verdict;
  actualScore: number;
  expectedVerdict: Verdict;
  expectedMinScore: number;
  expectedMaxScore: number;
  executionTimeMs: number;
  signalsFound: string[];
  failureReason?: string;
  analysis: SecurityAnalysisResult;
}

export interface TestSuiteOutcome {
  total: number;
  passed: number;
  failed: number;
  passRate: number;
  totalTimeMs: number;
  results: TestRunResult[];
}

/**
 * Executes security test suite against detection engine
 */
export async function runSecurityTestSuite(): Promise<TestSuiteOutcome> {
  const startTime = performance.now();
  const results: TestRunResult[] = [];
  let passedCount = 0;

  for (const testCase of SECURITY_TEST_CASES) {
    const t0 = performance.now();
    const analysis = analyzePageSecurity(
      testCase.url,
      testCase.mockForm,
      testCase.mockRedirect,
      undefined,
      testCase.mockSocial,
      testCase.mockDownload
    );
    const executionTimeMs = Math.round(performance.now() - t0);

    let passed = true;
    let failureReason: string | undefined;

    // Check verdict match
    if (analysis.verdict !== testCase.expectedVerdict) {
      if (!((testCase.expectedVerdict === 'HIGH_RISK' || testCase.expectedVerdict === 'DANGEROUS') &&
            (analysis.verdict === 'HIGH_RISK' || analysis.verdict === 'DANGEROUS'))) {
        passed = false;
        failureReason = `Expected verdict "${testCase.expectedVerdict}", but got "${analysis.verdict}" (Score: ${analysis.score})`;
      }
    }

    // Check score bounds
    if (analysis.score < testCase.expectedMinScore || analysis.score > testCase.expectedMaxScore) {
      passed = false;
      failureReason = `Score ${analysis.score} outside expected range [${testCase.expectedMinScore}, ${testCase.expectedMaxScore}]`;
    }

    // Check expected signals
    for (const expectedSig of testCase.expectedSignals) {
      const hasSignal = analysis.signals.some(s => s.type === expectedSig);
      if (!hasSignal) {
        passed = false;
        failureReason = `Expected signal "${expectedSig}" was not triggered`;
        break;
      }
    }

    if (passed) {
      passedCount++;
    }

    results.push({
      id: testCase.id,
      testName: testCase.name,
      category: testCase.category,
      description: testCase.description,
      passed,
      actualVerdict: analysis.verdict,
      actualScore: analysis.score,
      expectedVerdict: testCase.expectedVerdict,
      expectedMinScore: testCase.expectedMinScore,
      expectedMaxScore: testCase.expectedMaxScore,
      executionTimeMs,
      signalsFound: analysis.signals.map(s => s.title),
      failureReason,
      analysis
    });
  }

  const totalTimeMs = Math.round(performance.now() - startTime);
  const total = SECURITY_TEST_CASES.length;
  const passRate = total > 0 ? Math.round((passedCount / total) * 100) : 100;

  return {
    total,
    passed: passedCount,
    failed: total - passedCount,
    passRate,
    totalTimeMs,
    results
  };
}
