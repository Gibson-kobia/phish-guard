import { DetectionSignal, SocialEngineeringMetadata } from '../types';

/**
 * Social Engineering & Coercive Phishing Heuristics:
 * Analyzes non-sensitive structural text cues (headings, title, call-to-action buttons)
 * for coercive patterns, fake security alerts, and artificial urgency.
 */

const URGENCY_PATTERNS: Array<{ pattern: RegExp; phrase: string; weight: number }> = [
  { pattern: /account\s+(is\s+)?(temporarily\s+)?(suspended|locked|restricted|disabled|on\s+hold)/i, phrase: 'Account suspension / restriction notice', weight: 20 },
  { pattern: /(immediate(ly)?|urgent|24\s*hours?|within\s*\d+\s*hours?)\s+to\s+(verify|update|confirm|restore|reactivate)/i, phrase: 'Urgent compliance deadline', weight: 22 },
  { pattern: /unauthorized\s+(activity|access|transaction|sign-in|login)\s+detected/i, phrase: 'Deceptive unauthorized activity alert', weight: 20 },
  { pattern: /action\s+required\s*:\s*(verify|update|confirm|security)/i, phrase: 'Coercive action required prompt', weight: 15 },
  { pattern: /security\s+alert\s*:\s*(unusual|suspicious)\s+activity/i, phrase: 'Deceptive security alert heading', weight: 18 }
];

const CREDENTIAL_VERIFICATION_PATTERNS: Array<{ pattern: RegExp; phrase: string; weight: number }> = [
  { pattern: /verify\s+your\s+(identity|account|credentials|password|email|information)/i, phrase: 'Identity / credential verification prompt', weight: 16 },
  { pattern: /confirm\s+your\s+(password|passcode|secret\s+key|recovery\s+phrase|seed)/i, phrase: 'Password / recovery phrase confirmation prompt', weight: 25 },
  { pattern: /restore\s+(access\s+to\s+)?your\s+account/i, phrase: 'Account restoration cue', weight: 14 },
  { pattern: /re-?(authenticate|enter|login)\s+to\s+(continue|proceed|verify)/i, phrase: 'Forced re-authentication prompt', weight: 15 }
];

const PAYMENT_URGENCY_PATTERNS: Array<{ pattern: RegExp; phrase: string; weight: number }> = [
  { pattern: /payment\s+(declined|overdue|failed|expired|suspended)/i, phrase: 'Payment declined / billing failure claim', weight: 18 },
  { pattern: /update\s+(your\s+)?(billing|credit\s+card|payment\s+method)\s+(immediately|now|to\s+avoid)/i, phrase: 'Urgent billing update demand', weight: 22 },
  { pattern: /unpaid\s+(invoice|toll|delivery\s+fee|customs\s+fee)/i, phrase: 'Fake unpaid delivery / invoice claim', weight: 18 }
];

const TECH_SUPPORT_PATTERNS: Array<{ pattern: RegExp; phrase: string; weight: number }> = [
  { pattern: /(windows|microsoft|apple|chrome)\s+(security|defender|firewall)\s+alert/i, phrase: 'Impersonated system / OS security alert', weight: 30 },
  { pattern: /call\s+(support|toll-?free|help\s*desk|\+?1[-\s\d]{9,})/i, phrase: 'Fake toll-free tech support prompt', weight: 28 },
  { pattern: /(trojan|virus|malware|spyware)\s+detected\s+on\s+your\s+computer/i, phrase: 'Deceptive malware infection scare screen', weight: 32 },
  { pattern: /do\s+not\s+(shut\s+down|restart|close)\s+(your\s+computer|this\s+window)/i, phrase: 'Browser locker coercion phrase', weight: 25 }
];

const PRIZE_REWARD_PATTERNS: Array<{ pattern: RegExp; phrase: string; weight: number }> = [
  { pattern: /(congratulations|you\s+have\s+been\s+selected|lucky\s+winner)/i, phrase: 'Reward / lottery winner lure', weight: 20 },
  { pattern: /claim\s+(your\s+)?(\$\d+|\d+\s*gift\s*card|free\s+reward|iphone)/i, phrase: 'Prize claim lure', weight: 22 }
];

/**
 * Evaluates extracted non-sensitive page text cues for social engineering signatures
 */
export function evaluateSocialEngineering(
  metadata?: SocialEngineeringMetadata | null
): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  if (!metadata) return signals;

  // 1. Tech support scam scare screens
  if (metadata.hasFakeTechSupportLanguage) {
    signals.push({
      id: 'SIGNAL_SOCENG_TECH_SUPPORT',
      category: 'SOCIAL_ENGINEERING',
      type: 'FAKE_TECH_SUPPORT_SCAM',
      severity: 'CRITICAL',
      weight: 35,
      title: 'Deceptive Tech Support / Scareware Language',
      description: 'Page contains language simulating system security warnings or demanding immediate phone calls to support lines.',
      evidence: { phrases: metadata.detectedPhrases },
      confidence: 0.92
    });
  }

  // 2. Urgent account suspension / deadline threats
  if (metadata.hasAccountSuspensionNotice || metadata.hasUrgencyLanguage) {
    signals.push({
      id: 'SIGNAL_SOCENG_URGENCY',
      category: 'SOCIAL_ENGINEERING',
      type: 'COERCIVE_URGENCY_WARNING',
      severity: 'HIGH',
      weight: 22,
      title: 'Coercive Urgency or Account Suspension Threat',
      description: 'Page uses artificial deadlines or suspension threats to coerce rapid user action without verification.',
      evidence: { phrases: metadata.detectedPhrases },
      confidence: 0.85
    });
  }

  // 3. Credential verification lure
  if (metadata.hasCredentialVerificationPrompt) {
    signals.push({
      id: 'SIGNAL_SOCENG_CREDENTIAL_LURE',
      category: 'SOCIAL_ENGINEERING',
      type: 'CREDENTIAL_VERIFICATION_LURE',
      severity: 'MEDIUM',
      weight: 18,
      title: 'Deceptive Credential / Identity Verification Request',
      description: 'Page prompts the visitor to re-enter sensitive passwords, passcodes, or recovery phrases under the guise of account verification.',
      evidence: { phrases: metadata.detectedPhrases },
      confidence: 0.82
    });
  }

  // 4. Payment urgency or fake delivery fee
  if (metadata.hasPaymentUrgency) {
    signals.push({
      id: 'SIGNAL_SOCENG_PAYMENT_URGENCY',
      category: 'SOCIAL_ENGINEERING',
      type: 'PAYMENT_BILLING_URGENCY',
      severity: 'HIGH',
      weight: 24,
      title: 'Urgent Payment / Billing Problem Claim',
      description: 'Page claims an urgent payment failure, unpaid delivery fee, or billing disruption requiring immediate card details.',
      evidence: { phrases: metadata.detectedPhrases },
      confidence: 0.88
    });
  }

  // 5. Prize or reward scam
  if (metadata.hasPrizeOrRewardClaim) {
    signals.push({
      id: 'SIGNAL_SOCENG_PRIZE_LURE',
      category: 'SOCIAL_ENGINEERING',
      type: 'PRIZE_REWARD_LURE',
      severity: 'HIGH',
      weight: 25,
      title: 'Prize / Reward Social Engineering Lure',
      description: 'Page presents an unsolicited lottery win, gift card, or reward claim designed to elicit personal details.',
      evidence: { phrases: metadata.detectedPhrases },
      confidence: 0.86
    });
  }

  return signals;
}

/**
 * Extracts privacy-safe visible structural text cues from DOM
 * Examines only: <title>, <h1>, <h2>, <h3>, <button>, and [role="alert"]
 * Never inspects input field values, cookies, or user typed data.
 */
export function extractSocialEngineeringFromDocument(doc: Document): SocialEngineeringMetadata {
  const visibleHeadingsSample: string[] = [];
  const detectedPhrases: string[] = [];

  let hasUrgencyLanguage = false;
  let hasAccountSuspensionNotice = false;
  let hasCredentialVerificationPrompt = false;
  let hasFakeTechSupportLanguage = false;
  let hasPaymentUrgency = false;
  let hasPrizeOrRewardClaim = false;

  // Extract from title
  if (doc.title) {
    visibleHeadingsSample.push(doc.title.trim().slice(0, 120));
  }

  // Extract from prominent structural elements
  const elements = Array.from(
    doc.querySelectorAll('h1, h2, h3, button, [role="alert"], .alert, .warning, .modal-title, .banner-title')
  ).slice(0, 15);

  for (const el of elements) {
    const text = (el.textContent || '').trim().replace(/\s+/g, ' ');
    if (text.length > 3 && text.length < 150) {
      visibleHeadingsSample.push(text);
    }
  }

  const combinedText = visibleHeadingsSample.join(' | ');

  // Test Urgency
  for (const item of URGENCY_PATTERNS) {
    if (item.pattern.test(combinedText)) {
      hasUrgencyLanguage = true;
      if (item.phrase.includes('suspension')) hasAccountSuspensionNotice = true;
      detectedPhrases.push(item.phrase);
    }
  }

  // Test Credential Verification
  for (const item of CREDENTIAL_VERIFICATION_PATTERNS) {
    if (item.pattern.test(combinedText)) {
      hasCredentialVerificationPrompt = true;
      detectedPhrases.push(item.phrase);
    }
  }

  // Test Payment Urgency
  for (const item of PAYMENT_URGENCY_PATTERNS) {
    if (item.pattern.test(combinedText)) {
      hasPaymentUrgency = true;
      detectedPhrases.push(item.phrase);
    }
  }

  // Test Tech Support
  for (const item of TECH_SUPPORT_PATTERNS) {
    if (item.pattern.test(combinedText)) {
      hasFakeTechSupportLanguage = true;
      detectedPhrases.push(item.phrase);
    }
  }

  // Test Prize / Reward
  for (const item of PRIZE_REWARD_PATTERNS) {
    if (item.pattern.test(combinedText)) {
      hasPrizeOrRewardClaim = true;
      detectedPhrases.push(item.phrase);
    }
  }

  return {
    hasUrgencyLanguage,
    hasAccountSuspensionNotice,
    hasCredentialVerificationPrompt,
    hasFakeTechSupportLanguage,
    hasPaymentUrgency,
    hasPrizeOrRewardClaim,
    detectedPhrases: Array.from(new Set(detectedPhrases)),
    visibleHeadingsSample: visibleHeadingsSample.slice(0, 5)
  };
}
