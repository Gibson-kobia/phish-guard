import { DEFAULT_SETTINGS } from '../config/rules.js';

let currentSettings = { ...DEFAULT_SETTINGS };

document.addEventListener('DOMContentLoaded', async () => {
  await loadSettings();
  setupListeners();
});

async function loadSettings() {
  const data = await chrome.storage.local.get('settings');
  currentSettings = { ...DEFAULT_SETTINGS, ...(data.settings || {}) };

  // Set checkboxes
  document.getElementById('protectionEnabled').checked = currentSettings.protectionEnabled ?? true;
  document.getElementById('enableUrlAnalysis').checked = currentSettings.enableUrlAnalysis ?? true;
  document.getElementById('enableTyposquatting').checked = currentSettings.enableTyposquatting ?? true;
  document.getElementById('enableDomAnalysis').checked = currentSettings.enableDomAnalysis ?? true;
  document.getElementById('enableSocialEngineering').checked = currentSettings.enableSocialEngineering ?? true;
  document.getElementById('enableDownloadContext').checked = currentSettings.enableDownloadContext ?? true;
  document.getElementById('enableRedirectAnalysis').checked = currentSettings.enableRedirectAnalysis ?? true;
  document.getElementById('enableReputationLayer').checked = currentSettings.enableReputationLayer ?? true;
  document.getElementById('developerMode').checked = currentSettings.developerMode ?? false;

  // Sensitivity radio
  const radios = document.getElementsByName('detectionSensitivity');
  for (const r of radios) {
    if (r.value === (currentSettings.detectionSensitivity || 'BALANCED')) {
      r.checked = true;
    }
  }

  // Sliders
  const warningSlider = document.getElementById('warningThreshold');
  const blockSlider = document.getElementById('blockThreshold');
  
  warningSlider.value = currentSettings.warningThreshold ?? 70;
  document.getElementById('warningVal').textContent = warningSlider.value;

  blockSlider.value = currentSettings.blockThreshold ?? 90;
  document.getElementById('blockVal').textContent = blockSlider.value;

  // Fleet configuration
  const backendUrlInput = document.getElementById('fleetBackendUrl');
  if (backendUrlInput) {
    backendUrlInput.value = currentSettings.backendUrl || (typeof window !== 'undefined' && window.location.origin ? window.location.origin : 'http://localhost:3000');
  }

  const enrollmentTokenInput = document.getElementById('fleetEnrollmentToken');
  if (enrollmentTokenInput) {
    enrollmentTokenInput.value = currentSettings.enrollmentToken || '';
  }

  // Fetch background device status & Status Model
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'PHISHGUARD_GET_DEVICE_INFO' }, (resp) => {
        if (resp) {
          updateStatusSection(resp.statusModel, resp);
        }
      });
    }
  } catch (e) {
    // Ignore context error
  }

  // Render tag clouds
  renderTags('allowlistContainer', currentSettings.allowlist || [], (val) => {
    currentSettings.allowlist = (currentSettings.allowlist || []).filter(d => d !== val);
    saveSettings();
    loadSettings();
  });

  renderTags('blocklistContainer', currentSettings.blocklist || [], (val) => {
    currentSettings.blocklist = (currentSettings.blocklist || []).filter(d => d !== val);
    saveSettings();
    loadSettings();
  });
}

function setupListeners() {
  // Checkbox bindings
  const checkboxMap = [
    { id: 'protectionEnabled', key: 'protectionEnabled' },
    { id: 'enableUrlAnalysis', key: 'enableUrlAnalysis' },
    { id: 'enableTyposquatting', key: 'enableTyposquatting' },
    { id: 'enableDomAnalysis', key: 'enableDomAnalysis' },
    { id: 'enableSocialEngineering', key: 'enableSocialEngineering' },
    { id: 'enableDownloadContext', key: 'enableDownloadContext' },
    { id: 'enableRedirectAnalysis', key: 'enableRedirectAnalysis' },
    { id: 'enableReputationLayer', key: 'enableReputationLayer' },
    { id: 'developerMode', key: 'developerMode' }
  ];

  checkboxMap.forEach(({ id, key }) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('change', (e) => {
        currentSettings[key] = e.target.checked;
        saveSettings();
      });
    }
  });

  // Radio bindings
  const radios = document.getElementsByName('detectionSensitivity');
  for (const r of radios) {
    r.addEventListener('change', (e) => {
      if (e.target.checked) {
        currentSettings.detectionSensitivity = e.target.value;
        saveSettings();
      }
    });
  }

  // Slider bindings
  const warningSlider = document.getElementById('warningThreshold');
  warningSlider.addEventListener('input', (e) => {
    document.getElementById('warningVal').textContent = e.target.value;
    currentSettings.warningThreshold = parseInt(e.target.value, 10);
    saveSettings();
  });

  const blockSlider = document.getElementById('blockThreshold');
  blockSlider.addEventListener('input', (e) => {
    document.getElementById('blockVal').textContent = e.target.value;
    currentSettings.blockThreshold = parseInt(e.target.value, 10);
    saveSettings();
  });

  // Allowlist add
  document.getElementById('addAllowlistBtn').addEventListener('click', () => {
    const input = document.getElementById('allowlistInput');
    const val = input.value.trim().toLowerCase();
    if (val) {
      currentSettings.allowlist = currentSettings.allowlist || [];
      if (!currentSettings.allowlist.includes(val)) {
        currentSettings.allowlist.push(val);
        input.value = '';
        saveSettings();
        loadSettings();
      }
    }
  });

  // Blocklist add
  document.getElementById('addBlocklistBtn').addEventListener('click', () => {
    const input = document.getElementById('blocklistInput');
    const val = input.value.trim().toLowerCase();
    if (val) {
      currentSettings.blocklist = currentSettings.blocklist || [];
      if (!currentSettings.blocklist.includes(val)) {
        currentSettings.blocklist.push(val);
        input.value = '';
        saveSettings();
        loadSettings();
      }
    }
  });

  // Fleet enroll / sync button
  const fleetEnrollBtn = document.getElementById('fleetEnrollBtn');
  if (fleetEnrollBtn) {
    fleetEnrollBtn.addEventListener('click', async () => {
      const urlInput = document.getElementById('fleetBackendUrl');
      const tokenInput = document.getElementById('fleetEnrollmentToken');
      const stateEl = document.getElementById('fleetEnrollState');
      const devEl = document.getElementById('fleetDeviceId');
      const headlineEl = document.getElementById('optionsHeadline');
      const sublineEl = document.getElementById('optionsSubline');
      const badgeEl = document.getElementById('optionsStatusBadge');

      const backendUrl = (urlInput?.value || '').trim() || (typeof window !== 'undefined' && window.location.origin ? window.location.origin : 'http://localhost:3000');
      const enrollmentToken = (tokenInput?.value || '').trim();

      if (!enrollmentToken) {
        if (stateEl) {
          stateEl.textContent = 'Please enter an Enrollment Token';
          stateEl.style.color = '#F59E0B';
        }
        return;
      }

      currentSettings.backendUrl = backendUrl;
      currentSettings.enrollmentToken = enrollmentToken;
      await chrome.storage.local.set({ settings: currentSettings });

      if (stateEl) {
        stateEl.textContent = 'Enrolling & Syncing...';
        stateEl.style.color = '#F59E0B';
      }

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'PHISHGUARD_SYNC_NOW',
          backendUrl,
          enrollmentToken
        }, (resp) => {
          if (resp) {
            updateStatusSection(resp.statusModel, resp);
          }
        });
      }
      showSaveIndicator();
    });
  }

  // Fleet disconnect button (Return to individual mode)
  const fleetDisconnectBtn = document.getElementById('fleetDisconnectBtn');
  if (fleetDisconnectBtn) {
    fleetDisconnectBtn.addEventListener('click', async () => {
      const tokenInput = document.getElementById('fleetEnrollmentToken');
      if (tokenInput) tokenInput.value = '';
      currentSettings.enrollmentToken = '';
      await chrome.storage.local.set({ settings: currentSettings });

      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'PHISHGUARD_DISCONNECT_FLEET' }, (resp) => {
          if (resp) {
            updateStatusSection(resp.statusModel, resp);
          }
        });
      }
      showSaveIndicator();
    });
  }

  // Reset
  document.getElementById('resetDefaultsBtn').addEventListener('click', async () => {
    currentSettings = { ...DEFAULT_SETTINGS };
    await chrome.storage.local.set({ settings: currentSettings });
    loadSettings();
    showSaveIndicator();
  });

  // Clear History
  document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
    await chrome.storage.local.set({ history: [] });
    showSaveIndicator();
  });
}

function renderTags(containerId, list, onRemove) {
  const container = document.getElementById(containerId);
  container.textContent = '';

  if (!list || list.length === 0) {
    const emptyMsg = document.createElement('span');
    emptyMsg.style.color = '#64748B';
    emptyMsg.style.fontSize = '11px';
    emptyMsg.textContent = 'No entries configured.';
    container.appendChild(emptyMsg);
    return;
  }

  list.forEach(item => {
    const tag = document.createElement('div');
    tag.className = 'tag-item';

    const span = document.createElement('span');
    span.textContent = item;

    const removeBtn = document.createElement('span');
    removeBtn.className = 'tag-remove';
    removeBtn.textContent = '×';
    removeBtn.onclick = () => onRemove(item);

    tag.appendChild(span);
    tag.appendChild(removeBtn);
    container.appendChild(tag);
  });
}

async function saveSettings() {
  await chrome.storage.local.set({ settings: currentSettings });
  showSaveIndicator();
}

function updateStatusSection(sm, raw) {
  const headlineEl = document.getElementById('optionsHeadline');
  const sublineEl = document.getElementById('optionsSubline');
  const badgeEl = document.getElementById('optionsStatusBadge');
  const localProtEl = document.getElementById('statLocalProtection');
  const enrollEl = document.getElementById('statEnrollment');
  const syncEl = document.getElementById('statSync');
  const lastSyncEl = document.getElementById('statLastSync');
  const orgEl = document.getElementById('statOrganization');
  const queueEl = document.getElementById('statQueueCount');
  const devEl = document.getElementById('fleetDeviceId');

  if (sm) {
    if (headlineEl) headlineEl.textContent = sm.headline;
    if (sublineEl) sublineEl.textContent = sm.subline;
    if (badgeEl) {
      badgeEl.textContent = sm.badgeLabel;
      badgeEl.className = `status-pill ${sm.badgeVariant}`;
    }

    if (localProtEl) {
      localProtEl.textContent = sm.localProtection === 'LOCAL_PROTECTION_ACTIVE' ? 'ACTIVE' : 'PAUSED';
      localProtEl.style.color = sm.localProtection === 'LOCAL_PROTECTION_ACTIVE' ? '#34D399' : '#F59E0B';
    }

    if (enrollEl) {
      enrollEl.textContent = sm.cloudEnrollment.replace(/_/g, ' ');
      enrollEl.style.color = sm.cloudEnrollment === 'ENROLLED' ? '#34D399' : 
                             sm.cloudEnrollment === 'ENROLLING' ? '#38BDF8' :
                             sm.cloudEnrollment === 'NOT_ENROLLED' ? '#94A3B8' : '#EF4444';
    }

    if (syncEl) {
      syncEl.textContent = sm.cloudSync === 'CLOUD_OFFLINE' ? 'OFFLINE' : sm.cloudSync.replace(/_/g, ' ');
      syncEl.style.color = sm.cloudSync === 'SYNCED' ? '#34D399' :
                           sm.cloudSync === 'SYNCING' ? '#38BDF8' :
                           sm.cloudSync === 'CLOUD_OFFLINE' ? '#F59E0B' : 
                           sm.cloudSync === 'NOT_APPLICABLE' ? '#64748B' : '#EF4444';
    }

    if (lastSyncEl) {
      if (sm.lastSyncTime && sm.lastSyncTime > 0) {
        lastSyncEl.textContent = new Date(sm.lastSyncTime).toLocaleTimeString();
      } else {
        lastSyncEl.textContent = 'Never';
      }
    }

    if (orgEl) {
      orgEl.textContent = sm.cloudEnrollment === 'ENROLLED' && sm.organizationName ? sm.organizationName : 'Not enrolled';
      orgEl.style.color = sm.cloudEnrollment === 'ENROLLED' ? '#38BDF8' : '#64748B';
    }

    if (queueEl) {
      queueEl.textContent = `${sm.queueSize || 0} events`;
      queueEl.style.color = (sm.queueSize || 0) > 0 ? '#38BDF8' : '#64748B';
    }

    if (devEl) {
      devEl.textContent = sm.deviceId || raw?.deviceId || '-';
    }
  } else if (raw) {
    if (devEl && raw.deviceId) devEl.textContent = raw.deviceId;
    if (localProtEl) localProtEl.textContent = raw.localProtectionActive ? 'ACTIVE' : 'PAUSED';
    if (enrollEl) enrollEl.textContent = raw.enrolled ? 'ENROLLED' : 'NOT ENROLLED';
    if (orgEl) orgEl.textContent = raw.enrolled && raw.organizationId ? raw.organizationId : 'Not enrolled';
  }
}

function showSaveIndicator() {
  const status = document.getElementById('saveStatus');
  status.classList.add('show');
  setTimeout(() => {
    status.classList.remove('show');
  }, 1800);
}
