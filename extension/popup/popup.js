import { analyzePageSecurity } from '../engine/riskScoring.js';
import { DEFAULT_SETTINGS } from '../config/rules.js';

let currentTab = null;
let currentAnalysis = null;
let currentSettings = null;

document.addEventListener('DOMContentLoaded', async () => {
  // Navigation Tabs Setup
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetView = document.getElementById(
        targetId === 'overview' ? 'viewOverview' : targetId === 'timeline' ? 'viewTimeline' : 'viewHistory'
      );
      if (targetView) targetView.classList.add('active');

      if (targetId === 'history') {
        loadHistory();
      }
    });
  });

  // Action Buttons
  document.getElementById('rescanBtn').addEventListener('click', handleRescan);
  document.getElementById('optionsBtn').addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });
  document.getElementById('clearHistoryBtn')?.addEventListener('click', handleClearHistory);
  document.getElementById('quickAllowlistBtn')?.addEventListener('click', handleQuickAllowlist);

  // Debug Accordion
  const debugToggle = document.getElementById('toggleDebugBtn');
  if (debugToggle) {
    debugToggle.addEventListener('click', () => {
      const content = document.getElementById('debugContent');
      const arrow = document.getElementById('debugArrow');
      const isHidden = content.classList.contains('hidden');
      if (isHidden) {
        content.classList.remove('hidden');
        arrow.textContent = '▲';
      } else {
        content.classList.add('hidden');
        arrow.textContent = '▼';
      }
    });
  }

  // Load Settings
  const storage = await chrome.storage.local.get('settings');
  currentSettings = { ...DEFAULT_SETTINGS, ...(storage.settings || {}) };

  // Fetch Endpoint Status Model (Distinguishes Local Protection vs Managed vs Cloud Offline)
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'PHISHGUARD_GET_STATUS_MODEL' }, (resp) => {
        if (resp && resp.statusModel) {
          renderStatusModel(resp.statusModel);
        }
      });
    }
  } catch {}

  // Load Active Tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      currentTab = tabs[0];
      await loadTabSecurity(currentTab);
    }
  } catch (err) {
    console.error('Error fetching tab:', err);
    renderFallback('Unable to access current tab URL.');
  }
});

async function loadTabSecurity(tab) {
  if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
    renderSystemPage(tab?.url || 'Internal Browser Page');
    return;
  }

  document.getElementById('domainName').textContent = 'Analyzing ' + tab.url;

  // Ask service worker for cached analysis
  chrome.runtime.sendMessage({
    type: 'GET_CURRENT_ANALYSIS',
    tabId: tab.id
  }, async (response) => {
    if (response && response.result) {
      currentAnalysis = response.result;
      renderAnalysis(currentAnalysis);
    } else {
      // Fallback: Perform local analysis
      const result = analyzePageSecurity(tab.url, null, null, currentSettings);
      currentAnalysis = result;
      renderAnalysis(result);
    }
  });
}

function renderAnalysis(analysis) {
  if (!analysis) return;

  const statusCard = document.getElementById('statusCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const targetBrandBadge = document.getElementById('targetBrandBadge');
  const scoreValue = document.getElementById('scoreValue');
  const domainName = document.getElementById('domainName');
  const reasonsList = document.getElementById('reasonsList');
  const signalsContainer = document.getElementById('signalsContainer');
  const signalsCount = document.getElementById('signalsCount');
  const scanTime = document.getElementById('scanTime');
  const timelineContainer = document.getElementById('timelineContainer');
  const quickAllowlistContainer = document.getElementById('quickAllowlistContainer');

  // Status card theme class (safe, low_risk, suspicious, high_risk, dangerous)
  statusCard.className = 'status-card ' + analysis.verdict.toLowerCase();

  // 5-Tier Verdict labels
  const verdictDisplayMap = {
    SAFE: 'SAFE',
    LOW_RISK: 'LOW RISK',
    SUSPICIOUS: 'SUSPICIOUS',
    HIGH_RISK: 'HIGH RISK',
    DANGEROUS: 'DANGEROUS'
  };

  verdictBadge.textContent = verdictDisplayMap[analysis.verdict] || 'SAFE';
  scoreValue.textContent = analysis.score;
  domainName.textContent = analysis.domain || analysis.url;
  scanTime.textContent = (analysis.scanDurationMs || 0) + 'ms';

  // Target Brand Tag
  if (analysis.targetBrand) {
    targetBrandBadge.classList.remove('hidden');
    targetBrandBadge.textContent = `Mimics ${analysis.targetBrand.name}`;
  } else {
    targetBrandBadge.classList.add('hidden');
  }

  // Allowlist Button Visibility
  if (analysis.verdict !== 'SAFE') {
    quickAllowlistContainer.classList.remove('hidden');
  } else {
    quickAllowlistContainer.classList.add('hidden');
  }

  // Reasons List
  reasonsList.textContent = '';
  if (analysis.reasons && analysis.reasons.length > 0) {
    for (const r of analysis.reasons) {
      const li = document.createElement('li');
      li.className = 'reason-item ' + (
        analysis.verdict === 'DANGEROUS' || analysis.verdict === 'HIGH_RISK' ? 'danger' :
        analysis.verdict === 'SUSPICIOUS' ? 'warning' : 'safe'
      );
      li.textContent = r;
      reasonsList.appendChild(li);
    }
  }

  // Evidence / Signals List
  signalsContainer.textContent = '';
  signalsCount.textContent = (analysis.signals || []).length;

  if (!analysis.signals || analysis.signals.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.style.cssText = 'padding: 12px; color: #64748B; font-size: 11px; text-align: center;';
    emptyDiv.textContent = 'No threat signals or suspicious behaviors detected.';
    signalsContainer.appendChild(emptyDiv);
  } else {
    for (const sig of analysis.signals) {
      const card = document.createElement('div');
      card.className = 'signal-card';

      const header = document.createElement('div');
      header.className = 'signal-header';

      const title = document.createElement('span');
      title.className = 'signal-title';
      title.textContent = sig.title;

      const tag = document.createElement('span');
      tag.className = 'signal-tag ' + sig.severity;
      tag.textContent = sig.severity;

      header.appendChild(title);
      header.appendChild(tag);

      const desc = document.createElement('p');
      desc.className = 'signal-desc';
      desc.textContent = sig.description;

      card.appendChild(header);
      card.appendChild(desc);
      signalsContainer.appendChild(card);
    }
  }

  // Chronological Security Activity Timeline
  if (timelineContainer) {
    timelineContainer.textContent = '';
    const timeline = analysis.timeline || [];

    if (timeline.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.style.cssText = 'padding: 12px; color: #64748B; font-size: 11px; text-align: center;';
      emptyDiv.textContent = 'No security timeline events recorded.';
      timelineContainer.appendChild(emptyDiv);
    } else {
      for (const ev of timeline) {
        const item = document.createElement('div');
        item.className = 'timeline-item';

        const dot = document.createElement('div');
        dot.className = 'timeline-dot ' + (ev.severity || 'SAFE').toLowerCase();

        const content = document.createElement('div');
        content.className = 'timeline-content';

        const top = document.createElement('div');
        top.className = 'timeline-top';

        const title = document.createElement('span');
        title.className = 'timeline-title';
        title.textContent = ev.title;

        const time = document.createElement('span');
        time.className = 'timeline-time';
        time.textContent = ev.timeString || '';

        top.appendChild(title);
        top.appendChild(time);

        const desc = document.createElement('p');
        desc.className = 'timeline-desc';
        desc.textContent = ev.description;

        content.appendChild(top);
        content.appendChild(desc);

        item.appendChild(dot);
        item.appendChild(content);
        timelineContainer.appendChild(item);
      }
    }
  }

  // Developer Diagnostics Section
  const debugSection = document.getElementById('debugSection');
  if (currentSettings?.developerMode) {
    debugSection.classList.remove('hidden');
    document.getElementById('debugTime').textContent = (analysis.scanDurationMs || 0) + 'ms';
    document.getElementById('debugIp').textContent = analysis.features?.url?.isIpAddress ? 'Yes' : 'No';
    document.getElementById('debugForms').textContent = analysis.features?.form ? analysis.features.form.formsCount : '0';
    document.getElementById('debugPuny').textContent = analysis.features?.url?.isPunycode ? 'Yes' : 'No';
    document.getElementById('debugRaw').textContent = JSON.stringify({
      score: analysis.score,
      verdict: analysis.verdict,
      signalsCount: (analysis.signals || []).length,
      features: analysis.features
    }, null, 2);
  } else {
    debugSection.classList.add('hidden');
  }
}

async function loadHistory() {
  const historyContainer = document.getElementById('historyContainer');
  if (!historyContainer) return;

  historyContainer.textContent = '';
  const data = await chrome.storage.local.get('history');
  const history = data.history || [];

  if (history.length === 0) {
    const emptyDiv = document.createElement('div');
    emptyDiv.style.cssText = 'padding: 16px; color: #64748B; font-size: 11px; text-align: center;';
    emptyDiv.textContent = 'No recent security assessments recorded yet.';
    historyContainer.appendChild(emptyDiv);
    return;
  }

  for (const item of history) {
    const card = document.createElement('div');
    card.className = 'history-item ' + item.verdict.toLowerCase();

    const top = document.createElement('div');
    top.className = 'history-top';

    const domain = document.createElement('span');
    domain.className = 'history-domain';
    domain.textContent = item.domain;

    const badge = document.createElement('span');
    badge.className = 'history-badge ' + item.verdict.toLowerCase();
    badge.textContent = `${item.score}/100`;

    top.appendChild(domain);
    top.appendChild(badge);

    const sig = document.createElement('p');
    sig.className = 'history-signal';
    sig.textContent = item.topSignal || 'Clean baseline';

    card.appendChild(top);
    card.appendChild(sig);
    historyContainer.appendChild(card);
  }
}

async function handleClearHistory() {
  await chrome.storage.local.set({ history: [] });
  loadHistory();
}

async function handleQuickAllowlist() {
  if (!currentAnalysis || !currentAnalysis.domain) return;
  const domain = currentAnalysis.domain.toLowerCase();

  const data = await chrome.storage.local.get('settings');
  const settings = data.settings || DEFAULT_SETTINGS;
  const allowlist = Array.from(new Set([...(settings.allowlist || []), domain]));

  await chrome.storage.local.set({ settings: { ...settings, allowlist } });

  // Rescan
  handleRescan();
}

async function handleRescan() {
  if (!currentTab) return;
  const btn = document.getElementById('rescanBtn');
  btn.style.transform = 'rotate(180deg)';

  chrome.runtime.sendMessage({
    type: 'FORCE_RESCAN',
    tabId: currentTab.id,
    url: currentTab.url
  }, (response) => {
    if (response?.result) {
      currentAnalysis = response.result;
      renderAnalysis(response.result);
    }
    setTimeout(() => {
      btn.style.transform = 'none';
    }, 300);
  });
}

function renderSystemPage(url) {
  document.getElementById('statusCard').className = 'status-card safe';
  document.getElementById('verdictBadge').textContent = 'INTERNAL';
  document.getElementById('scoreValue').textContent = '0';
  document.getElementById('domainName').textContent = url;

  const reasonsList = document.getElementById('reasonsList');
  reasonsList.textContent = '';
  const li = document.createElement('li');
  li.className = 'reason-item safe';
  li.textContent = 'Internal browser system page (safe by default).';
  reasonsList.appendChild(li);

  document.getElementById('signalsCount').textContent = '0';
  const signalsContainer = document.getElementById('signalsContainer');
  signalsContainer.textContent = '';
  const emptyDiv = document.createElement('div');
  emptyDiv.style.cssText = 'padding: 12px; color: #64748B; font-size: 11px; text-align: center;';
  emptyDiv.textContent = 'Zero active analysis required for browser internal URLs.';
  signalsContainer.appendChild(emptyDiv);
}

function renderFallback(msg) {
  document.getElementById('domainName').textContent = msg;
}

function renderStatusModel(statusModel) {
  if (!statusModel) return;
  const banner = document.getElementById('endpointStatusBanner');
  const dot = document.getElementById('statusIndicatorDot');
  const headline = document.getElementById('statusHeadline');
  const subline = document.getElementById('statusSubline');
  const badge = document.getElementById('statusBadge');

  if (!banner || !headline || !subline || !badge) return;

  const variant = statusModel.badgeVariant || (statusModel.state === 'SYNCED' ? 'managed' : statusModel.state === 'CLOUD_OFFLINE' ? 'offline' : 'safe');

  banner.className = `endpoint-status-banner ${variant}`;
  if (dot) dot.className = `status-dot ${variant}`;
  headline.textContent = statusModel.headline || 'Protected locally';
  subline.textContent = statusModel.subline || 'PhishGuard is actively checking websites in this browser.';
  badge.className = `status-pill ${variant}`;
  badge.textContent = statusModel.badgeLabel || (variant === 'managed' ? 'Managed' : variant === 'offline' ? 'Offline' : 'Local');
}
