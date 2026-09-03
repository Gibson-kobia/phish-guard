import { DetectionSignal, FormAnalysisMetadata } from '../types';
import { isTrustedFederatedProvider } from '../config/trustedProviders';

/**
 * Evaluates extracted DOM form metadata for credential harvesting, insecure HTTP, and rogue cross-origin endpoints
 */
export function evaluateFormSecurity(
  pageUrl: string,
  formMeta?: FormAnalysisMetadata | null
): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  if (!formMeta) return signals;

  let pageHost = '';
  try {
    const parsed = new URL(pageUrl.startsWith('http') ? pageUrl : 'https://' + pageUrl);
    pageHost = parsed.hostname.toLowerCase();
  } catch {
    pageHost = pageUrl.toLowerCase();
  }

  // 1. Password Field Present
  if (formMeta.hasPasswordInput) {
    signals.push({
      id: 'SIGNAL_PASSWORD_INPUT_PRESENT',
      category: 'DOM_SECURITY',
      type: 'CREDENTIAL_INPUT_FIELD',
      severity: 'LOW',
      weight: 15,
      title: 'Credential / Password Entry Field Present',
      description: 'The webpage presents a password or credential entry field, indicating an active authentication surface.',
      confidence: 0.95
    });
  }

  // 2. Financial / Identity Data Collection
  if (formMeta.hasCreditCardInput || formMeta.hasSsnInput) {
    signals.push({
      id: 'SIGNAL_FINANCIAL_INPUT_PRESENT',
      category: 'DOM_SECURITY',
      type: 'FINANCIAL_DATA_COLLECTION',
      severity: 'MEDIUM',
      weight: 25,
      title: 'Payment or Identity Data Input Field Present',
      description: 'Page contains input fields explicitly requesting credit card numbers, CVVs, or Social Security numbers.',
      confidence: 0.90
    });
  }

  // 3. Insecure Form Action (Submitting to unencrypted HTTP)
  const insecureForms = (formMeta.suspiciousForms || []).filter(f => f.isInsecureHttp);
  if (insecureForms.length > 0) {
    signals.push({
      id: 'SIGNAL_INSECURE_FORM_ACTION',
      category: 'DOM_SECURITY',
      type: 'INSECURE_HTTP_FORM_SUBMISSION',
      severity: 'HIGH',
      weight: 40,
      title: 'Form Submits Credentials Over Insecure HTTP',
      description: 'Form submission endpoint uses unencrypted HTTP protocol. Entered data can be intercepted by network eavesdroppers.',
      confidence: 0.95,
      evidence: { insecureFormsCount: insecureForms.length }
    });
  }

  // 4. Cross-Origin Form Action with Password Field (Credential Exfiltration Dropper)
  // Distinguish legitimate federated login (OAuth/SSO/Stripe) vs rogue cross-origin drop point
  const rogueCrossOriginForms = (formMeta.suspiciousForms || []).filter(f => {
    if (!f.isCrossOrigin || !f.hasPasswordField) return false;
    let actionHost = '';
    try {
      actionHost = new URL(f.action, pageUrl).hostname.toLowerCase();
    } catch {
      actionHost = '';
    }
    const { isTrusted } = isTrustedFederatedProvider(actionHost);
    return !isTrusted;
  });

  if (rogueCrossOriginForms.length > 0) {
    signals.push({
      id: 'SIGNAL_CROSS_ORIGIN_CREDENTIAL_FORM',
      category: 'DOM_SECURITY',
      type: 'CROSS_ORIGIN_CREDENTIAL_HARVESTER',
      severity: 'CRITICAL',
      weight: 60,
      title: 'Cross-Origin Credential Form Action (Data Drop)',
      description: 'The login form submits entered credentials to an unrelated external domain. This is a primary signature of credential harvesters.',
      confidence: 0.96,
      evidence: {
        pageHost,
        crossOriginActions: rogueCrossOriginForms.map(f => f.action)
      }
    });
  }

  // 5. Excessive Hidden Input Fields on Login Form
  if (formMeta.hasHiddenCredentialFields) {
    signals.push({
      id: 'SIGNAL_EXCESSIVE_HIDDEN_FIELDS',
      category: 'DOM_SECURITY',
      type: 'SUSPICIOUS_HIDDEN_FORM_FIELDS',
      severity: 'LOW',
      weight: 12,
      title: 'Excessive Hidden State Fields in Auth Form',
      description: 'Authentication form includes numerous hidden fields, often utilized by phishing kits to pass stolen session and campaign tracker tags.',
      confidence: 0.70
    });
  }

  // 6. Cryptographic / 2FA Token Input
  if (formMeta.has2FAInput) {
    signals.push({
      id: 'SIGNAL_2FA_INTERCEPTION',
      category: 'DOM_SECURITY',
      type: '2FA_OTP_INTERCEPTION_FIELD',
      severity: 'MEDIUM',
      weight: 20,
      title: 'Two-Factor / Passcode Request Field',
      description: 'Page requests OTP authentication tokens, 2FA codes, or cryptocurrency seed phrases.',
      confidence: 0.85
    });
  }

  return signals;
}

/**
 * Utility for content scripts or client-side simulator to safely extract DOM form features
 * WITHOUT capturing user input values, passwords, cookies, or secrets
 */
export function extractDomMetadataFromDocument(doc: Document, windowOrigin: string): FormAnalysisMetadata {
  const passwordInputs = doc.querySelectorAll('input[type="password"]');
  const hasPasswordInput = passwordInputs.length > 0;

  const emailOrUserInputs = doc.querySelectorAll(
    'input[type="email"], input[name*="user" i], input[name*="login" i], input[id*="user" i], input[id*="login" i], input[autocomplete="username"], input[autocomplete="email"]'
  );
  const hasEmailOrUserInput = emailOrUserInputs.length > 0;

  const ccInputs = doc.querySelectorAll(
    'input[name*="card" i], input[name*="cc-" i], input[name*="cvv" i], input[id*="card" i], input[autocomplete*="cc-" i]'
  );
  const hasCreditCardInput = ccInputs.length > 0;

  const ssnInputs = doc.querySelectorAll(
    'input[name*="ssn" i], input[name*="social-security" i], input[id*="ssn" i]'
  );
  const hasSsnInput = ssnInputs.length > 0;

  const twoFaInputs = doc.querySelectorAll(
    'input[name*="otp" i], input[name*="2fa" i], input[name*="token" i], input[id*="otp" i], input[id*="2fa" i], input[name*="seed" i], input[name*="mnemonic" i]'
  );
  const has2FAInput = twoFaInputs.length > 0;

  const forms = Array.from(doc.querySelectorAll('form'));
  let hasHiddenCredentialFields = false;

  let currentHost = '';
  try {
    currentHost = new URL(windowOrigin).hostname.toLowerCase();
  } catch {
    currentHost = windowOrigin.toLowerCase();
  }

  const suspiciousForms = forms.map(form => {
    const rawAction = form.getAttribute('action') || '';
    let isCrossOrigin = false;
    let isInsecureHttp = false;

    if (rawAction && !rawAction.startsWith('javascript:') && !rawAction.startsWith('#')) {
      try {
        const actionUrl = new URL(rawAction, windowOrigin);
        const actionHost = actionUrl.hostname.toLowerCase();
        isCrossOrigin = actionHost !== currentHost && !actionHost.endsWith('.' + currentHost);
        isInsecureHttp = actionUrl.protocol === 'http:';
      } catch {
        // relative action or malformed
      }
    }

    const formPasswordFields = form.querySelectorAll('input[type="password"]');
    const hiddenInputs = form.querySelectorAll('input[type="hidden"]');
    if (formPasswordFields.length > 0 && hiddenInputs.length > 5) {
      hasHiddenCredentialFields = true;
    }

    return {
      action: rawAction,
      method: (form.getAttribute('method') || 'GET').toUpperCase(),
      isCrossOrigin,
      isInsecureHttp,
      hasPasswordField: formPasswordFields.length > 0,
      inputCount: form.querySelectorAll('input, select, textarea').length,
      hiddenInputsCount: hiddenInputs.length
    };
  });

  const externalScripts: string[] = [];
  try {
    const scriptTags = Array.from(doc.querySelectorAll('script[src]'));
    for (const s of scriptTags.slice(0, 10)) {
      const src = s.getAttribute('src');
      if (src && src.startsWith('http')) {
        externalScripts.push(src);
      }
    }
  } catch {
    // ignore
  }

  return {
    hasPasswordInput,
    hasCreditCardInput,
    hasSsnInput,
    hasEmailOrUserInput,
    has2FAInput,
    formsCount: forms.length,
    suspiciousForms,
    hasHiddenCredentialFields,
    hasExternalScriptSources: externalScripts,
    pageTitle: doc.title
  };
}
