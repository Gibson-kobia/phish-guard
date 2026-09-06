import { analyzePageSecurity } from '../engine/riskScoring.js';
import { DEFAULT_SETTINGS } from '../config/rules.js';

let targetUrl = '';
let targetDomain = '';

document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  targetUrl = urlParams.get('url') || 'Unknown Destination';
  
  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : 'https://' + targetUrl);
    targetDomain = parsed.hostname;
  } catch {
    targetDomain = targetUrl;
  }

  document.getElementById('targetUrl').textContent = targetUrl;

  // Setup buttons
  document.getElementById('safetyBtn').addEventListener('click', () => {
    window.history.back();
    setTimeout(() => {
      window.location.href = 'https://www.google.com';
    }, 400);
  });

  const advancedToggle = document.getElementById('advancedToggleBtn');
  advancedToggle.addEventListener('click', () => {
    const area = document.getElementById('advancedArea');
    area.classList.toggle('hidden');
  });

  document.getElementById('bypassBtn').addEventListener('click', async () => {
    chrome.runtime.sendMessage({
      type: 'DISMISS_WARNING_FOR_DOMAIN',
      domain: targetDomain
    }, () => {
      window.location.href = targetUrl;
    });
  });

  document.getElementById('allowlistBtn').addEventListener('click', async () => {
    const data = await chrome.storage.local.get('settings');
    const settings = data.settings || DEFAULT_SETTINGS;
    const allowlist = settings.allowlist || [];

    if (!allowlist.includes(targetDomain)) {
      allowlist.push(targetDomain);
      settings.allowlist = allowlist;
      await chrome.storage.local.set({ settings });
    }

    chrome.runtime.sendMessage({
      type: 'DISMISS_WARNING_FOR_DOMAIN',
      domain: targetDomain
    }, () => {
      window.location.href = targetUrl;
    });
  });

  // Run full analysis to display all signals and evidence
  await loadSignals();
});

async function loadSignals() {
  const storage = await chrome.storage.local.get('settings');
  const settings = storage.settings || DEFAULT_SETTINGS;
  const analysis = analyzePageSecurity(targetUrl, null, null, settings);

  document.getElementById('targetScore').textContent = `${analysis.score} / 100`;
  
  const riskBadge = document.getElementById('riskBadge');
  riskBadge.textContent = analysis.score >= 80 ? 'CRITICAL RISK' : 'HIGH RISK';

  const listContainer = document.getElementById('signalsList');
  listContainer.textContent = '';

  if (!analysis.signals || analysis.signals.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.style.color = '#94A3B8';
    emptyDiv.style.fontSize = '12px';
    emptyDiv.textContent = 'No specific threat signals recorded.';
    listContainer.appendChild(emptyDiv);
    return;
  }

  for (const sig of analysis.signals) {
    const item = document.createElement('div');
    item.className = 'signal-item';

    const header = document.createElement('div');
    header.className = 'signal-item-header';

    const title = document.createElement('span');
    title.className = 'signal-item-title';
    title.textContent = sig.title;

    const sev = document.createElement('span');
    sev.className = 'signal-item-severity ' + sig.severity;
    sev.textContent = sig.severity;

    header.appendChild(title);
    header.appendChild(sev);

    const desc = document.createElement('p');
    desc.className = 'signal-item-desc';
    desc.textContent = sig.description;

    item.appendChild(header);
    item.appendChild(desc);
    listContainer.appendChild(item);
  }
}
