/**
 * PhishGuard Form Security Event Analyzer
 * 
 * Constructs structured form interaction events.
 * 
 * STRICT PRIVACY MANDATE:
 * Only inspects structural HTML tags and attributes (<input type="password">, 2FA prompts, form actions).
 * NEVER captures or stores user input values, passwords, credit card numbers, or OTP codes.
 */

import { FormSecurityEvent, ThreatSeverity } from './eventTypes';
import { extractRegisteredDomain } from '../engine/brandIdentity';

export interface RawFormObservation {
  tabId: number;
  pageUrl: string;
  action?: string;
  method?: string;
  hasPasswordField?: boolean;
  hasCreditCardField?: boolean;
  has2FAField?: boolean;
  hasEmailOrUserField?: boolean;
  inputCount?: number;
  hiddenFieldCount?: number;
}

export function createFormSecurityEvent(
  formOrTabId: RawFormObservation | number | null | undefined,
  pageUrlArg?: string,
  formMetadataArg?: any
): FormSecurityEvent | null {
  let tabId = 0;
  let pageUrl = '';
  let action = '';
  let method = 'POST';
  let hasPasswordField = false;
  let hasCreditCardField = false;
  let has2FAField = false;
  let hasEmailOrUserField = false;
  let inputCount = 0;
  let hiddenFieldCount = 0;

  if (typeof formOrTabId === 'number') {
    tabId = formOrTabId;
    pageUrl = typeof pageUrlArg === 'string' ? pageUrlArg : '';
    if (formMetadataArg && typeof formMetadataArg === 'object') {
      action = typeof formMetadataArg.action === 'string' ? formMetadataArg.action : '';
      method = typeof formMetadataArg.method === 'string' ? formMetadataArg.method : 'POST';
      hasPasswordField = !!(formMetadataArg.hasPasswordField || formMetadataArg.hasPasswordInput);
      hasCreditCardField = !!(formMetadataArg.hasCreditCardField || formMetadataArg.hasCreditCardInput);
      has2FAField = !!(formMetadataArg.has2FAField || formMetadataArg.has2FAInput);
      hasEmailOrUserField = !!(formMetadataArg.hasEmailOrUserField || formMetadataArg.hasEmailOrUserInput);
      inputCount = typeof formMetadataArg.inputCount === 'number' ? formMetadataArg.inputCount : (formMetadataArg.formsCount || 0);
      hiddenFieldCount = typeof formMetadataArg.hiddenFieldCount === 'number' ? formMetadataArg.hiddenFieldCount : 0;
      
      // If suspiciousForms array exists
      if (Array.isArray(formMetadataArg.suspiciousForms) && formMetadataArg.suspiciousForms.length > 0) {
        const primaryForm = formMetadataArg.suspiciousForms[0];
        if (primaryForm.action) action = primaryForm.action;
        if (primaryForm.method) method = primaryForm.method;
        if (primaryForm.hasPasswordField) hasPasswordField = true;
      }
    }
  } else if (formOrTabId && typeof formOrTabId === 'object') {
    tabId = typeof formOrTabId.tabId === 'number' ? formOrTabId.tabId : 0;
    pageUrl = typeof formOrTabId.pageUrl === 'string' ? formOrTabId.pageUrl : '';
    action = typeof formOrTabId.action === 'string' ? formOrTabId.action : '';
    method = typeof formOrTabId.method === 'string' ? formOrTabId.method : 'POST';
    hasPasswordField = !!formOrTabId.hasPasswordField;
    hasCreditCardField = !!formOrTabId.hasCreditCardField;
    has2FAField = !!formOrTabId.has2FAField;
    hasEmailOrUserField = !!formOrTabId.hasEmailOrUserField;
    inputCount = typeof formOrTabId.inputCount === 'number' ? formOrTabId.inputCount : 0;
    hiddenFieldCount = typeof formOrTabId.hiddenFieldCount === 'number' ? formOrTabId.hiddenFieldCount : 0;
  }

  if (!pageUrl && !action) {
    return null;
  }

  let pageHostname = '';
  let actionHostname = '';
  let pageOrigin = '';

  try {
    const pageParsed = new URL(pageUrl.startsWith('http') ? pageUrl : 'https://' + pageUrl);
    pageHostname = pageParsed.hostname.toLowerCase();
    pageOrigin = pageParsed.origin;
  } catch {
    pageHostname = pageUrl.toLowerCase();
    pageOrigin = pageUrl;
  }

  try {
    if (action && (action.startsWith('http') || action.startsWith('//'))) {
      const actionUrl = action.startsWith('//') ? 'https:' + action : action;
      const actionParsed = new URL(actionUrl);
      actionHostname = actionParsed.hostname.toLowerCase();
    } else {
      // Relative action points to same page origin
      actionHostname = pageHostname;
    }
  } catch {
    actionHostname = pageHostname;
  }

  const pageRegDomain = extractRegisteredDomain(pageHostname);
  const actionRegDomain = extractRegisteredDomain(actionHostname);
  const actionIsCrossOrigin = actionHostname !== '' && pageRegDomain !== '' && actionRegDomain !== '' && actionRegDomain !== pageRegDomain;
  const actionIsInsecure = action.toLowerCase().startsWith('http://');

  let formType: FormSecurityEvent['formType'] = 'GENERIC';
  if (has2FAField) {
    formType = 'VERIFICATION_2FA';
  } else if (hasCreditCardField) {
    formType = 'PAYMENT';
  } else if (hasPasswordField) {
    formType = 'LOGIN';
  } else if (hasEmailOrUserField) {
    formType = 'REGISTRATION';
  }

  let severity: ThreatSeverity = 'LOW';
  let eventType: FormSecurityEvent['type'] = 'CREDENTIAL_FORM_DETECTED';
  let title = 'Form Detected';
  let description = `Standard ${formType} form present.`;

  if (actionIsCrossOrigin && (hasPasswordField || hasCreditCardField || has2FAField)) {
    severity = 'CRITICAL';
    eventType = 'CROSS_ORIGIN_FORM_ACTION';
    title = 'Cross-Origin Credential Exfiltration Target';
    description = `Form collects sensitive credentials but submits to external domain (${actionHostname}) rather than page origin (${pageHostname}).`;
  } else if (actionIsInsecure && (hasPasswordField || hasCreditCardField)) {
    severity = 'HIGH';
    eventType = 'INSECURE_FORM_DETECTED';
    title = 'Insecure Unencrypted Credential Submission';
    description = 'Form submits authentication credentials over unencrypted HTTP.';
  } else if (has2FAField) {
    severity = 'MEDIUM';
    eventType = 'VERIFICATION_CODE_FORM_DETECTED';
    title = 'Two-Factor Verification Code Form';
    description = 'Form requests one-time verification passcode (2FA / OTP).';
  } else if (hasCreditCardField) {
    severity = 'MEDIUM';
    eventType = 'PAYMENT_FORM_DETECTED';
    title = 'Financial Payment Collection Form';
    description = 'Form requests credit card or banking information.';
  } else if (hasPasswordField) {
    severity = 'LOW';
    eventType = 'CREDENTIAL_FORM_DETECTED';
    title = 'Authentication Credential Form';
    description = 'Form contains password input fields.';
  }

  return {
    id: `form_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: Date.now(),
    tabId,
    pageUrl,
    pageOrigin,
    type: eventType,
    severity,
    title,
    description,
    formType,
    actionUrl: action,
    actionHostname,
    actionIsCrossOrigin,
    actionIsInsecure,
    hasPasswordField,
    hasCreditCardField,
    has2FAField,
    inputCount,
    hiddenFieldCount,
    evidence: {
      formType,
      actionHostname,
      actionIsCrossOrigin,
      actionIsInsecure,
      hasPasswordField,
      hasCreditCardField,
      has2FAField
    }
  };
}
