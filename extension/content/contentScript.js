/**
 * PhishGuard Content Script
 * 
 * Inspects page structure, form metadata, and non-sensitive structural text cues
 * without capturing user inputs, passwords, tokens, cookies, or keystrokes.
 * Complies with strict privacy-first constraints.
 * 
 * Includes:
 * 1. Deep DOM & Open Shadow-DOM form element detection
 * 2. Real-time throttled SPA MutationObserver
 * 3. 3-Tier In-Page Warning UX:
 *    - SAFE: Silent
 *    - SUSPICIOUS (40-59): Polite top banner
 *    - DANGEROUS / HIGH_RISK (>=60): High-visibility warning overlay card
 * 4. Pre-flight form submission security guard
 */

(function () {
  'use strict';

  // Prevent duplicate execution
  if (window.__PHISHGUARD_INITIALIZED__) return;
  window.__PHISHGUARD_INITIALIZED__ = true;

  let currentAnalysis = null;
  let lastReportedHash = '';
  let mutationTimeout = null;
  let lastScanTime = 0;
  let isWarningDismissedForSession = false;

  const THROTTLE_MS = 1200;
  const MAX_WAIT_MS = 3500;

  const URGENCY_REGEX = /account\s+(is\s+)?(temporarily\s+)?(suspended|locked|restricted|disabled|on\s+hold)|(immediate(ly)?|urgent|24\s*hours?|within\s*\d+\s*hours?)\s+to\s+(verify|update|confirm|restore|reactivate)|unauthorized\s+(activity|access|transaction|sign-in|login)\s+detected|action\s+required\s*:\s*(verify|update|confirm|security)|security\s+alert\s*:\s*(unusual|suspicious)\s+activity/i;
  const CREDENTIAL_REGEX = /verify\s+your\s+(identity|account|credentials|password|email|information)|confirm\s+your\s+(password|passcode|secret\s+key|recovery\s+phrase|seed)|restore\s+(access\s+to\s+)?your\s+account|re-?(authenticate|enter|login)\s+to\s+(continue|proceed|verify)/i;
  const PAYMENT_REGEX = /payment\s+(declined|overdue|failed|expired|suspended)|update\s+(your\s+)?(billing|credit\s+card|payment\s+method)\s+(immediately|now|to\s+avoid)|unpaid\s+(invoice|toll|delivery\s+fee|customs\s+fee)/i;
  const TECH_SUPPORT_REGEX = /(windows|microsoft|apple|chrome)\s+(security|defender|firewall)\s+alert|call\s+(support|toll-?free|help\s*desk|\+?1[-\s\d]{9,})|(trojan|virus|malware|spyware)\s+detected\s+on\s+your\s+computer|do\s+not\s+(shut\s+down|restart|close)\s+(your\s+computer|this\s+window)/i;
  const PRIZE_REGEX = /(congratulations|you\s+have\s+been\s+selected|lucky\s+winner)|claim\s+(your\s+)?(\$\d+|\d+\s*gift\s*card|free\s+reward|iphone)/i;

  /**
   * Recursively traverses root and open shadow roots to find form elements safely
   */
  function queryAllShadow(selector, root = document) {
    const results = Array.from(root.querySelectorAll(selector));
    const allElements = root.querySelectorAll('*');
    for (const el of allElements) {
      if (el.shadowRoot) {
        results.push(...queryAllShadow(selector, el.shadowRoot));
      }
    }
    return results;
  }

  /**
   * Safely inspects the DOM for forms, inputs, and structural social engineering text cues
   */
  function inspectPageDOM() {
    lastScanTime = Date.now();
    try {
      // 1. Password & Credential Input Detection (including shadow DOM)
      const passwordInputs = queryAllShadow('input[type="password"]');
      const hasPasswordInput = passwordInputs.length > 0;

      const emailOrUserInputs = queryAllShadow(
        'input[type="email"], input[name*="user" i], input[name*="login" i], input[id*="user" i], input[id*="login" i], input[autocomplete="username"], input[autocomplete="email"]'
      );
      const hasEmailOrUserInput = emailOrUserInputs.length > 0;

      const ccInputs = queryAllShadow(
        'input[name*="card" i], input[name*="cc-" i], input[name*="cvv" i], input[id*="card" i], input[autocomplete*="cc-" i]'
      );
      const hasCreditCardInput = ccInputs.length > 0;

      const ssnInputs = queryAllShadow(
        'input[name*="ssn" i], input[name*="social-security" i], input[id*="ssn" i]'
      );
      const hasSsnInput = ssnInputs.length > 0;

      const twoFaInputs = queryAllShadow(
        'input[name*="otp" i], input[name*="2fa" i], input[name*="token" i], input[id*="otp" i], input[id*="2fa" i], input[name*="seed" i], input[name*="mnemonic" i]'
      );
      const has2FAInput = twoFaInputs.length > 0;

      const forms = queryAllShadow('form');
      let hasHiddenCredentialFields = false;
      const currentHost = window.location.hostname.toLowerCase();

      const suspiciousForms = forms.map(form => {
        const rawAction = form.getAttribute('action') || '';
        let isCrossOrigin = false;
        let isInsecureHttp = false;

        if (rawAction && !rawAction.startsWith('javascript:') && !rawAction.startsWith('#')) {
          try {
            const actionUrl = new URL(rawAction, window.location.href);
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

      const formMetadata = {
        hasPasswordInput,
        hasCreditCardInput,
        hasSsnInput,
        hasEmailOrUserInput,
        has2FAInput,
        formsCount: forms.length,
        suspiciousForms,
        hasHiddenCredentialFields,
        pageTitle: document.title
      };

      // 2. Structural Social Engineering & Branding Text Inspection
      const visibleHeadingsSample = [];
      const detectedPhrases = [];

      if (document.title) {
        visibleHeadingsSample.push(document.title.trim().slice(0, 120));
      }

      const structuralElements = Array.from(
        document.querySelectorAll('h1, h2, h3, button, [role="alert"], .alert, .warning, .modal-title, .banner-title, [class*="brand"], [class*="logo"]')
      ).slice(0, 15);

      for (const el of structuralElements) {
        const text = (el.textContent || '').trim().replace(/\s+/g, ' ');
        if (text.length > 3 && text.length < 150) {
          visibleHeadingsSample.push(text);
        }
      }

      const combinedText = visibleHeadingsSample.join(' | ');

      const hasUrgencyLanguage = URGENCY_REGEX.test(combinedText);
      const hasAccountSuspensionNotice = hasUrgencyLanguage && /suspend|locked|restrict/i.test(combinedText);
      const hasCredentialVerificationPrompt = CREDENTIAL_REGEX.test(combinedText);
      const hasPaymentUrgency = PAYMENT_REGEX.test(combinedText);
      const hasFakeTechSupportLanguage = TECH_SUPPORT_REGEX.test(combinedText);
      const hasPrizeOrRewardClaim = PRIZE_REGEX.test(combinedText);

      if (hasUrgencyLanguage) detectedPhrases.push('Urgency / suspension notice');
      if (hasCredentialVerificationPrompt) detectedPhrases.push('Credential verification prompt');
      if (hasPaymentUrgency) detectedPhrases.push('Payment billing urgency');
      if (hasFakeTechSupportLanguage) detectedPhrases.push('Fake tech support / alert phrase');
      if (hasPrizeOrRewardClaim) detectedPhrases.push('Prize / reward lure');

      const socialMeta = {
        hasUrgencyLanguage,
        hasAccountSuspensionNotice,
        hasCredentialVerificationPrompt,
        hasFakeTechSupportLanguage,
        hasPaymentUrgency,
        hasPrizeOrRewardClaim,
        detectedPhrases,
        visibleHeadingsSample: visibleHeadingsSample.slice(0, 5)
      };

      const stateHash = `${hasPasswordInput}_${hasCreditCardInput}_${forms.length}_${suspiciousForms.length}_${detectedPhrases.length}_${document.title}`;
      if (stateHash === lastReportedHash) return;
      lastReportedHash = stateHash;

      // Dispatch to background service worker
      chrome.runtime.sendMessage({
        type: 'PHISHGUARD_DOM_METADATA',
        url: window.location.href,
        formMetadata,
        socialMeta
      }, (response) => {
        if (response && response.analysis) {
          currentAnalysis = response.analysis;
          applyWarningExperience(response.analysis);
        }
      });

    } catch (e) {
      // Fail safely without disrupting host page
    }
  }

  // Pre-flight form submit security interception
  document.addEventListener('submit', (e) => {
    if (!currentAnalysis) return;
    if (isWarningDismissedForSession) return;

    const isHighRisk = currentAnalysis.score >= 60 || currentAnalysis.verdict === 'DANGEROUS' || currentAnalysis.verdict === 'HIGH_RISK';
    const form = e.target;
    if (form && isHighRisk) {
      const hasSensitiveFields = form.querySelector('input[type="password"], input[name*="card" i], input[name*="cc-" i], input[name*="otp" i]');
      if (hasSensitiveFields) {
        e.preventDefault();
        e.stopPropagation();

        const confirmed = window.confirm(
          `🛡️ PhishGuard Security Notice:\n\nThis website has been flagged as high-risk (${currentAnalysis.score}/100 - ${currentAnalysis.verdict}).\n\nSubmitting sensitive credentials or payment data here may expose your personal information.\n\nAre you sure you want to proceed?`
        );

        if (confirmed) {
          isWarningDismissedForSession = true;
          form.submit();
        }
      }
    }
  }, true);

  // Initial scan at document idle
  inspectPageDOM();

  // Throttled MutationObserver with Max-Wait Guarantee for dynamic single-page applications
  const observer = new MutationObserver(() => {
    const now = Date.now();
    if (now - lastScanTime > MAX_WAIT_MS) {
      if (mutationTimeout) clearTimeout(mutationTimeout);
      inspectPageDOM();
      return;
    }

    if (mutationTimeout) clearTimeout(mutationTimeout);
    mutationTimeout = setTimeout(() => {
      inspectPageDOM();
    }, THROTTLE_MS);
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  // Message listener for in-page security alerts from background
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'PHISHGUARD_SHOW_BANNER' && message.analysis) {
      currentAnalysis = message.analysis;
      applyWarningExperience(message.analysis);
    }
  });

  /**
   * Applies the appropriate warning experience based on calibrated threat severity
   */
  function applyWarningExperience(analysis) {
    if (isWarningDismissedForSession) return;
    if (!analysis || analysis.score < 40) return;

    if (analysis.score >= 60 || analysis.verdict === 'DANGEROUS' || analysis.verdict === 'HIGH_RISK') {
      renderHighRiskOverlayModal(analysis);
    } else if (analysis.score >= 40 || analysis.verdict === 'SUSPICIOUS') {
      renderSuspiciousTopBanner(analysis);
    }
  }

  /**
   * LEVEL 2 — SUSPICIOUS: Renders a lightweight, non-blocking top banner
   */
  function renderSuspiciousTopBanner(analysis) {
    if (document.getElementById('phishguard-warning-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'phishguard-warning-banner';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483646;
      background-color: #1E293B;
      color: #F8FAFC;
      border-bottom: 2px solid #F59E0B;
      padding: 10px 16px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 13px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;

    const contentDiv = document.createElement('div');
    contentDiv.style.cssText = 'display: flex; align-items: center; gap: 10px;';

    const iconSpan = document.createElement('span');
    iconSpan.textContent = '⚠️';
    iconSpan.style.fontSize = '16px';

    const textSpan = document.createElement('span');
    const strongTitle = document.createElement('strong');
    strongTitle.textContent = 'PhishGuard Caution: ';
    
    const bodyText = document.createTextNode(`This site has unverified or suspicious characteristics (Risk Score: ${analysis.score}/100). Exercise caution before entering passwords.`);

    textSpan.appendChild(strongTitle);
    textSpan.appendChild(bodyText);

    contentDiv.appendChild(iconSpan);
    contentDiv.appendChild(textSpan);

    const btnContainer = document.createElement('div');
    btnContainer.style.cssText = 'display: flex; align-items: center; gap: 8px;';

    const detailsBtn = document.createElement('button');
    detailsBtn.textContent = 'View Details';
    detailsBtn.style.cssText = `
      background: #334155;
      color: #fff;
      border: 1px solid #475569;
      padding: 4px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    `;
    detailsBtn.onclick = () => {
      const warningUrl = chrome.runtime.getURL(
        `warning/warning.html?url=${encodeURIComponent(analysis.url)}&score=${analysis.score}&verdict=${analysis.verdict}&domain=${encodeURIComponent(analysis.domain)}`
      );
      window.location.href = warningUrl;
    };

    const dismissBtn = document.createElement('button');
    dismissBtn.textContent = '✕';
    dismissBtn.style.cssText = `
      background: transparent;
      color: #94A3B8;
      border: none;
      padding: 4px 8px;
      cursor: pointer;
      font-size: 14px;
    `;
    dismissBtn.onclick = () => {
      isWarningDismissedForSession = true;
      banner.remove();
    };

    btnContainer.appendChild(detailsBtn);
    btnContainer.appendChild(dismissBtn);

    banner.appendChild(contentDiv);
    banner.appendChild(btnContainer);

    document.body.prepend(banner);
  }

  /**
   * LEVEL 3 — DANGEROUS / HIGH_RISK: Renders prominent in-page security modal card
   */
  function renderHighRiskOverlayModal(analysis) {
    if (document.getElementById('phishguard-risk-modal')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phishguard-risk-modal';
    overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(4px);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 20px;
      box-sizing: border-box;
    `;

    const card = document.createElement('div');
    card.style.cssText = `
      background: #0F172A;
      color: #F8FAFC;
      border: 1px solid #EF4444;
      border-radius: 12px;
      max-width: 520px;
      width: 100%;
      padding: 24px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
      display: flex;
      flex-direction: column;
      gap: 16px;
    `;

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'display: flex; align-items: center; justify-content: space-between;';

    const headerLeft = document.createElement('div');
    headerLeft.style.cssText = 'display: flex; align-items: center; gap: 12px;';

    const iconBadge = document.createElement('div');
    iconBadge.textContent = '⚠️';
    iconBadge.style.cssText = 'font-size: 24px; background: rgba(239, 68, 68, 0.15); border-radius: 8px; padding: 6px 10px;';

    const titleDiv = document.createElement('div');
    const titleH3 = document.createElement('h3');
    titleH3.textContent = 'This website may be unsafe';
    titleH3.style.cssText = 'margin: 0; font-size: 18px; font-weight: 700; color: #EF4444;';
    
    const subTitle = document.createElement('div');
    subTitle.textContent = `PhishGuard Threat Protection · ${analysis.domain}`;
    subTitle.style.cssText = 'font-size: 12px; color: #94A3B8; margin-top: 2px;';

    titleDiv.appendChild(titleH3);
    titleDiv.appendChild(subTitle);
    headerLeft.appendChild(iconBadge);
    headerLeft.appendChild(titleDiv);

    const scoreBadge = document.createElement('div');
    scoreBadge.textContent = `${analysis.score} / 100`;
    scoreBadge.style.cssText = 'background: #EF4444; color: #fff; font-weight: 700; font-size: 12px; padding: 4px 8px; border-radius: 6px;';

    header.appendChild(headerLeft);
    header.appendChild(scoreBadge);
    card.appendChild(header);

    // Primary summary
    const summaryP = document.createElement('p');
    summaryP.style.cssText = 'font-size: 14px; line-height: 1.5; color: #E2E8F0; margin: 0;';
    const topReason = analysis.reasons && analysis.reasons.length > 0 ? analysis.reasons[0] : 'This website shows deceptive characteristics commonly associated with credential theft.';
    summaryP.textContent = topReason;
    card.appendChild(summaryP);

    // Concerns list
    if (analysis.reasons && analysis.reasons.length > 1) {
      const reasonsList = document.createElement('ul');
      reasonsList.style.cssText = 'margin: 0; padding-left: 20px; font-size: 13px; color: #94A3B8; line-height: 1.5;';
      for (const reason of analysis.reasons.slice(1, 4)) {
        const li = document.createElement('li');
        li.textContent = reason;
        reasonsList.appendChild(li);
      }
      card.appendChild(reasonsList);
    }

    // Action Buttons
    const actionsDiv = document.createElement('div');
    actionsDiv.style.cssText = 'display: flex; gap: 10px; margin-top: 8px; flex-wrap: wrap;';

    const safeBackBtn = document.createElement('button');
    safeBackBtn.textContent = 'Go Back to Safety';
    safeBackBtn.style.cssText = `
      flex: 1;
      background: #2563EB;
      color: #fff;
      font-weight: 600;
      border: none;
      padding: 10px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      min-width: 140px;
    `;
    safeBackBtn.onclick = () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'chrome://newtab';
      }
    };

    const detailsBtn = document.createElement('button');
    detailsBtn.textContent = 'Why was this flagged?';
    detailsBtn.style.cssText = `
      background: #1E293B;
      color: #94A3B8;
      border: 1px solid #334155;
      padding: 10px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
    `;
    detailsBtn.onclick = () => {
      const warningUrl = chrome.runtime.getURL(
        `warning/warning.html?url=${encodeURIComponent(analysis.url)}&score=${analysis.score}&verdict=${analysis.verdict}&domain=${encodeURIComponent(analysis.domain)}`
      );
      window.location.href = warningUrl;
    };

    const continueBtn = document.createElement('button');
    continueBtn.textContent = 'Continue Anyway';
    continueBtn.style.cssText = `
      background: transparent;
      color: #64748B;
      border: none;
      padding: 10px 10px;
      cursor: pointer;
      font-size: 12px;
      text-decoration: underline;
    `;
    continueBtn.onclick = () => {
      isWarningDismissedForSession = true;
      overlay.remove();
    };

    actionsDiv.appendChild(safeBackBtn);
    actionsDiv.appendChild(detailsBtn);
    actionsDiv.appendChild(continueBtn);
    card.appendChild(actionsDiv);

    overlay.appendChild(card);
    document.body.prepend(overlay);
  }
})();
