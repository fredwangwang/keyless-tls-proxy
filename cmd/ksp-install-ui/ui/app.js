// Fred Proxy KSP UI Controller

const state = {
  activeTab: 'tab-connect',
  config: {
    addr: '',
    ca: 'certs/ca.crt',
    cert: 'certs/client.crt',
    key: 'certs/client.key',
    config_path: ''
  },
  remoteCerts: [],
  installedCerts: [],
  discoveredServers: [],
  isConnected: false,
  testSign: {
    isOpen: false,
    selectedThumbprint: '',
    mode: 'text',
    lastResult: null,
    sigFormat: 'base64'
  }
};

// DOM Elements
const elements = {
  // Navigation
  navItems: document.querySelectorAll('.nav-item[data-tab]'),
  tabPanes: document.querySelectorAll('.tab-pane'),
  pageTitle: document.getElementById('page-title'),
  pageSubtitle: document.getElementById('page-subtitle'),
  btnGlobalRefresh: document.getElementById('btn-global-refresh'),
  connDot: document.getElementById('conn-dot'),
  connText: document.getElementById('conn-text'),
  remoteCountBadge: document.getElementById('remote-count-badge'),
  installedCountBadge: document.getElementById('installed-count-badge'),
  btnHeaderTestSign: document.getElementById('btn-header-test-sign'),
  navBtnTestSign: document.getElementById('nav-btn-test-sign'),

  // Config & Connection
  inputAddr: document.getElementById('input-addr'),
  inputCA: document.getElementById('input-ca'),
  inputCert: document.getElementById('input-cert'),
  inputKey: document.getElementById('input-key'),
  inputConfigPath: document.getElementById('input-config-path'),
  btnTestConn: document.getElementById('btn-test-conn'),
  btnSaveConfig: document.getElementById('btn-save-config'),
  chipServerStatus: document.getElementById('chip-server-status'),
  testResultBox: document.getElementById('test-result-box'),

  // Discovery
  btnScanNetwork: document.getElementById('btn-scan-network'),
  scanBtnLabel: document.getElementById('scan-btn-label'),
  discoveryLoading: document.getElementById('discovery-loading'),
  discoveryList: document.getElementById('discovery-list'),

  // Remote Certs
  inputSearchRemote: document.getElementById('input-search-remote'),
  btnFetchRemote: document.getElementById('btn-fetch-remote'),
  btnEmptyFetch: document.getElementById('btn-empty-fetch'),
  remoteCertsContainer: document.getElementById('remote-certs-container'),
  remoteStatsText: document.getElementById('remote-stats-text'),

  // Installed Certs
  inputSearchInstalled: document.getElementById('input-search-installed'),
  btnReloadInstalled: document.getElementById('btn-reload-installed'),
  installedCertsContainer: document.getElementById('installed-certs-container'),
  installedStatsText: document.getElementById('installed-stats-text'),

  // Diagnostics
  diagProvider: document.getElementById('diag-provider'),
  diagDataDir: document.getElementById('diag-datadir'),
  diagConfigFile: document.getElementById('diag-configfile'),
  diagManifestFile: document.getElementById('diag-manifestfile'),
  diagKeyCount: document.getElementById('diag-keycount'),

  // Test Sign Drawer
  testSignBackdrop: document.getElementById('test-sign-backdrop'),
  testSignDrawer: document.getElementById('test-sign-drawer'),
  btnCloseTestSign: document.getElementById('btn-close-test-sign'),
  tsCertSelect: document.getElementById('ts-cert-select'),
  tsCertPreview: document.getElementById('ts-cert-preview'),
  tsPreviewSubject: document.getElementById('ts-preview-subject'),
  tsPreviewKeytype: document.getElementById('ts-preview-keytype'),
  tsPreviewThumbprint: document.getElementById('ts-preview-thumbprint'),
  tsPreviewProvider: document.getElementById('ts-preview-provider'),
  btnModeText: document.getElementById('btn-mode-text'),
  btnModeHex: document.getElementById('btn-mode-hex'),
  tsInputTextGroup: document.getElementById('ts-input-text-group'),
  tsInputHexGroup: document.getElementById('ts-input-hex-group'),
  tsInputMessage: document.getElementById('ts-input-message'),
  tsInputHex: document.getElementById('ts-input-hex'),
  tsHexHint: document.getElementById('ts-hex-hint'),
  tsHashSelect: document.getElementById('ts-hash-select'),
  tsPaddingGroup: document.getElementById('ts-padding-group'),
  tsPaddingSelect: document.getElementById('ts-padding-select'),
  tsEcdsaNote: document.getElementById('ts-ecdsa-note'),
  btnExecuteSign: document.getElementById('btn-execute-sign'),
  tsBtnLabel: document.getElementById('ts-btn-label'),
  tsResultContainer: document.getElementById('ts-result-container'),
  tsResultStatus: document.getElementById('ts-result-status'),
  tsResultDuration: document.getElementById('ts-result-duration'),
  tsResultAlg: document.getElementById('ts-result-alg'),
  tsResultHashname: document.getElementById('ts-result-hashname'),
  tsResultDigest: document.getElementById('ts-result-digest'),
  btnCopyDigest: document.getElementById('btn-copy-digest'),
  btnFmtBase64: document.getElementById('btn-fmt-base64'),
  btnFmtHex: document.getElementById('btn-fmt-hex'),
  btnCopySignature: document.getElementById('btn-copy-signature'),
  tsResultSignature: document.getElementById('ts-result-signature'),
  tsErrorBox: document.getElementById('ts-error-box'),

  // Modals & Toasts
  toastContainer: document.getElementById('toast-container'),
  confirmModal: document.getElementById('confirm-modal'),
  modalTitle: document.getElementById('modal-title'),
  modalBody: document.getElementById('modal-body'),
  btnModalClose: document.getElementById('btn-modal-close'),
  btnModalCancel: document.getElementById('btn-modal-cancel'),
  btnModalConfirm: document.getElementById('btn-modal-confirm')
};

const tabDescriptions = {
  'tab-connect': {
    title: 'Discover & Connect',
    subtitle: 'Configure server address, scan local network for TPM proxy servers, and setup mTLS certificates.'
  },
  'tab-remote': {
    title: 'Remote Certificates',
    subtitle: 'Inspect available certificates from the remote key server and bind them into Windows Certificate Store (KSP).'
  },
  'tab-installed': {
    title: 'Installed Local Certificates',
    subtitle: 'Manage local Windows Store (MY) certificates registered and bound to Fred Proxy Key Storage Provider.'
  },
  'tab-diagnostics': {
    title: 'Diagnostics & Info',
    subtitle: 'KSP provider registration status, CNG environment paths, and system configuration.'
  }
};

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  await loadInitialConfig();
  await loadInstalledCertificates();
  await loadDiagnostics();
});

// Setup Event Listeners
function setupEventListeners() {
  // Tab Navigation
  elements.navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabId = item.getAttribute('data-tab');
      switchTab(tabId);
    });
  });

  // Global Refresh Button
  elements.btnGlobalRefresh.addEventListener('click', async () => {
    const icon = elements.btnGlobalRefresh.querySelector('.icon-spin-target');
    icon.style.animation = 'spin 0.6s linear';
    setTimeout(() => { icon.style.animation = ''; }, 600);

    if (state.activeTab === 'tab-connect') {
      await loadInitialConfig();
      await startDiscovery();
    } else if (state.activeTab === 'tab-remote') {
      await fetchRemoteCertificates();
    } else if (state.activeTab === 'tab-installed') {
      await loadInstalledCertificates();
    } else if (state.activeTab === 'tab-diagnostics') {
      await loadDiagnostics();
    }
  });

  // Test Sign Drawer Triggers
  if (elements.btnHeaderTestSign) {
    elements.btnHeaderTestSign.addEventListener('click', () => openTestSignPanel());
  }
  if (elements.navBtnTestSign) {
    elements.navBtnTestSign.addEventListener('click', () => openTestSignPanel());
  }
  if (elements.btnCloseTestSign) {
    elements.btnCloseTestSign.addEventListener('click', closeTestSignPanel);
  }
  if (elements.testSignBackdrop) {
    elements.testSignBackdrop.addEventListener('click', closeTestSignPanel);
  }

  // Escape Key to Close Overlays
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (elements.confirmModal && !elements.confirmModal.classList.contains('hidden')) {
        hideConfirmModal();
      } else if (elements.testSignDrawer && elements.testSignDrawer.classList.contains('open')) {
        closeTestSignPanel();
      }
    }
  });

  // Test Sign Controls
  if (elements.tsCertSelect) {
    elements.tsCertSelect.addEventListener('change', onTestSignCertChanged);
  }
  if (elements.btnModeText) {
    elements.btnModeText.addEventListener('click', () => setPayloadMode('text'));
  }
  if (elements.btnModeHex) {
    elements.btnModeHex.addEventListener('click', () => setPayloadMode('hex'));
  }
  if (elements.tsHashSelect) {
    elements.tsHashSelect.addEventListener('change', updateHexHint);
  }
  if (elements.btnExecuteSign) {
    elements.btnExecuteSign.addEventListener('click', executeTestSign);
  }
  if (elements.btnFmtBase64) {
    elements.btnFmtBase64.addEventListener('click', () => setSignatureFormat('base64'));
  }
  if (elements.btnFmtHex) {
    elements.btnFmtHex.addEventListener('click', () => setSignatureFormat('hex'));
  }
  if (elements.btnCopyDigest) {
    elements.btnCopyDigest.addEventListener('click', () => {
      copyToClipboard(elements.tsResultDigest.textContent, 'Digest copied to clipboard!');
    });
  }
  if (elements.btnCopySignature) {
    elements.btnCopySignature.addEventListener('click', () => {
      copyToClipboard(elements.tsResultSignature.value, 'Signature copied to clipboard!');
    });
  }

  // Preset Buttons
  document.querySelectorAll('.preset-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const preset = pill.getAttribute('data-preset');
      const text = pill.getAttribute('data-text');
      if (preset === 'timestamp') {
        elements.tsInputMessage.value = `Fred Proxy KSP Ping - ${new Date().toISOString()} [Nonce: ${Math.random().toString(36).substring(2, 10)}]`;
      } else if (text) {
        elements.tsInputMessage.value = text;
      }
      setPayloadMode('text');
    });
  });

  // Connection & Config
  elements.btnTestConn.addEventListener('click', testConnection);
  elements.btnSaveConfig.addEventListener('click', saveConfig);

  // File Browsers
  document.querySelectorAll('.btn-browse').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.getAttribute('data-target');
      const filter = btn.getAttribute('data-filter') || 'All Files (*.*)|*.*';
      const parts = filter.split('|');
      const desc = parts[0] || 'All Files (*.*)';
      const pattern = parts[1] || '*.*';

      try {
        if (window.backend && window.backend.SelectFile) {
          const selected = await window.backend.SelectFile('Select Certificate/Key File', desc, pattern);
          if (selected) {
            document.getElementById(targetId).value = selected;
          }
        }
      } catch (err) {
        showToast(`File selection error: ${err}`, 'error');
      }
    });
  });

  // Discovery
  elements.btnScanNetwork.addEventListener('click', startDiscovery);

  // Remote Certs
  elements.btnFetchRemote.addEventListener('click', fetchRemoteCertificates);
  elements.btnEmptyFetch.addEventListener('click', () => {
    switchTab('tab-connect');
  });
  elements.inputSearchRemote.addEventListener('input', renderRemoteCertificates);

  // Installed Certs
  elements.btnReloadInstalled.addEventListener('click', loadInstalledCertificates);
  elements.inputSearchInstalled.addEventListener('input', renderInstalledCertificates);

  // Modal Controls
  elements.btnModalClose.addEventListener('click', hideConfirmModal);
  elements.btnModalCancel.addEventListener('click', hideConfirmModal);
}

// Switch Active Tab
function switchTab(tabId) {
  state.activeTab = tabId;

  elements.navItems.forEach(item => {
    item.classList.toggle('active', item.getAttribute('data-tab') === tabId);
  });

  elements.tabPanes.forEach(pane => {
    pane.classList.toggle('active', pane.id === tabId);
  });

  if (tabDescriptions[tabId]) {
    elements.pageTitle.textContent = tabDescriptions[tabId].title;
    elements.pageSubtitle.textContent = tabDescriptions[tabId].subtitle;
  }
}

// Current Config from Form
function getFormConfig() {
  return {
    addr: elements.inputAddr.value.trim(),
    ca: elements.inputCA.value.trim(),
    cert: elements.inputCert.value.trim(),
    key: elements.inputKey.value.trim(),
    config_path: elements.inputConfigPath.value.trim()
  };
}

// Load Initial Configuration
async function loadInitialConfig() {
  try {
    if (window.backend && window.backend.LoadConfig) {
      const cfg = await window.backend.LoadConfig();
      if (cfg) {
        state.config = cfg;
        elements.inputAddr.value = cfg.addr || '';
        elements.inputCA.value = cfg.ca || 'certs/ca.crt';
        elements.inputCert.value = cfg.cert || 'certs/client.crt';
        elements.inputKey.value = cfg.key || 'certs/client.key';
        elements.inputConfigPath.value = cfg.config_path || '';
      }
    }
  } catch (err) {
    showToast(`Failed to load config: ${err}`, 'error');
  }
}

// Save Configuration
async function saveConfig() {
  const cfg = getFormConfig();
  try {
    if (window.backend && window.backend.SaveConfig) {
      await window.backend.SaveConfig(cfg);
      showToast('Configuration saved successfully!', 'success');
    }
  } catch (err) {
    showToast(`Save failed: ${err}`, 'error');
  }
}

// Test Connection
async function testConnection() {
  const cfg = getFormConfig();
  if (!cfg.addr) {
    showToast('Please enter a server address', 'error');
    elements.inputAddr.focus();
    return;
  }

  elements.btnTestConn.disabled = true;
  elements.btnTestConn.innerHTML = '<span>Connecting...</span>';
  elements.testResultBox.classList.add('hidden');

  try {
    if (window.backend && window.backend.TestConnection) {
      const result = await window.backend.TestConnection(cfg);
      elements.chipServerStatus.className = 'chip chip-success';
      elements.chipServerStatus.textContent = 'Connected';
      elements.connDot.className = 'status-dot connected';
      elements.connText.textContent = cfg.addr;

      elements.testResultBox.className = 'message-box success';
      elements.testResultBox.textContent = result;
      elements.testResultBox.classList.remove('hidden');

      state.isConnected = true;
      showToast('Connected to remote server!', 'success');

      // Auto-fetch remote certs
      await fetchRemoteCertificates();
    }
  } catch (err) {
    elements.chipServerStatus.className = 'chip chip-danger';
    elements.chipServerStatus.textContent = 'Failed';
    elements.connDot.className = 'status-dot';
    elements.connText.textContent = 'Disconnected';

    elements.testResultBox.className = 'message-box error';
    elements.testResultBox.textContent = `Connection failed: ${err}`;
    elements.testResultBox.classList.remove('hidden');

    state.isConnected = false;
    showToast(`Connection failed: ${err}`, 'error');
  } finally {
    elements.btnTestConn.disabled = false;
    elements.btnTestConn.innerHTML = '<span>Test & Connect</span>';
  }
}

// Start Network Discovery
async function startDiscovery() {
  elements.btnScanNetwork.disabled = true;
  elements.scanBtnLabel.textContent = 'Scanning...';
  elements.discoveryLoading.classList.remove('hidden');

  try {
    if (window.backend && window.backend.DiscoverServers) {
      const servers = await window.backend.DiscoverServers(3);
      state.discoveredServers = servers || [];
      renderDiscoveredServers();
      if (servers && servers.length > 0) {
        showToast(`Discovered ${servers.length} server(s) on local network`, 'success');
      } else {
        showToast('No TPM cert servers discovered on local subnet', 'info');
      }
    }
  } catch (err) {
    showToast(`Discovery error: ${err}`, 'error');
  } finally {
    elements.btnScanNetwork.disabled = false;
    elements.scanBtnLabel.textContent = 'Scan (UDP)';
    elements.discoveryLoading.classList.add('hidden');
  }
}

// Render Discovered Servers List
function renderDiscoveredServers() {
  const container = elements.discoveryList;
  if (!state.discoveredServers || state.discoveredServers.length === 0) {
    container.innerHTML = `
      <div class="empty-state-sm">
        <span>No servers discovered. Make sure <code>tpm-cert-server</code> discovery is running on port :6666.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = state.discoveredServers.map(s => `
    <div class="server-item" onclick="selectDiscoveredServer('${s.grpc_addr}', '${s.hostname}')">
      <div class="server-meta">
        <strong>${escapeHtml(s.hostname || s.grpc_addr)}</strong>
        <span>Address: ${escapeHtml(s.grpc_addr)} (v${escapeHtml(s.version || '1')})</span>
      </div>
      <div class="server-action-tag">Click to Select &rarr;</div>
    </div>
  `).join('');
}

// Select a Discovered Server
window.selectDiscoveredServer = function(grpcAddr, hostname) {
  elements.inputAddr.value = grpcAddr;
  showToast(`Selected server: ${grpcAddr}`, 'info');
  testConnection();
};

// Fetch Remote Certificates
async function fetchRemoteCertificates() {
  const cfg = getFormConfig();
  if (!cfg.addr) {
    showToast('Please specify a server address on the Connect tab first', 'error');
    return;
  }

  elements.btnFetchRemote.disabled = true;
  elements.btnFetchRemote.innerHTML = '<span>Fetching...</span>';

  try {
    if (window.backend && window.backend.ListRemoteCertificates) {
      const certs = await window.backend.ListRemoteCertificates(cfg);
      state.remoteCerts = certs || [];
      elements.remoteCountBadge.textContent = state.remoteCerts.length;
      renderRemoteCertificates();
      showToast(`Loaded ${state.remoteCerts.length} remote certificate(s)`, 'success');
    }
  } catch (err) {
    showToast(`Failed to fetch certificates: ${err}`, 'error');
  } finally {
    elements.btnFetchRemote.disabled = false;
    elements.btnFetchRemote.innerHTML = '<span>Fetch Remote List</span>';
  }
}

// Render Remote Certificates Grid
function renderRemoteCertificates() {
  const container = elements.remoteCertsContainer;
  const filter = (elements.inputSearchRemote.value || '').toLowerCase().trim();

  const filtered = state.remoteCerts.filter(c => {
    if (!filter) return true;
    return (c.subject || '').toLowerCase().includes(filter) ||
           (c.thumbprint || '').toLowerCase().includes(filter) ||
           (c.key_algorithm || '').toLowerCase().includes(filter) ||
           (c.issuer || '').toLowerCase().includes(filter);
  });

  elements.remoteStatsText.textContent = `${filtered.length} of ${state.remoteCerts.length} certificates`;

  if (filtered.length === 0) {
    if (state.remoteCerts.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
          <h3>No Remote Certificates Found</h3>
          <p>The connected server has no certificates with private keys loaded.</p>
        </div>
      `;
    } else {
      container.innerHTML = `
        <div class="empty-state">
          <h3>No Matching Certificates</h3>
          <p>No certificates match your search query "${escapeHtml(filter)}".</p>
        </div>
      `;
    }
    return;
  }

  container.innerHTML = filtered.map(c => `
    <div class="cert-card ${c.is_installed ? 'installed' : ''}">
      <div>
        <div class="cert-card-header">
          <div class="cert-subject-group">
            <span class="cert-subject">${escapeHtml(c.subject || 'Unknown Subject')}</span>
            <span class="cert-issuer">Issuer: ${escapeHtml(c.issuer || 'Self-Signed / Root')}</span>
          </div>
          ${c.is_installed ? '<span class="chip chip-success">Installed</span>' : '<span class="chip chip-info">Remote</span>'}
        </div>

        <div class="cert-tags">
          <span class="cert-tag">${escapeHtml(c.key_algorithm || 'RSA')} ${c.key_size ? `${c.key_size}-bit` : ''}</span>
          ${c.is_expired ? '<span class="chip chip-danger">Expired</span>' : '<span class="chip chip-success">Valid</span>'}
          ${(c.key_usage || []).map(u => `<span class="cert-tag">${escapeHtml(u)}</span>`).join('')}
        </div>

        <div class="cert-thumbprint-box">
          <span class="cert-tp-text" title="SHA-1 Thumbprint">${formatThumbprint(c.thumbprint)}</span>
          <button class="btn-copy" onclick="copyToClipboard('${c.thumbprint}')" title="Copy Thumbprint">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>

        <div class="cert-details-meta">
          ${c.not_after ? `<div><strong>Expires:</strong> ${escapeHtml(c.not_after)} (${c.days_remaining} days left)</div>` : ''}
          ${c.sans && c.sans.length > 0 ? `<div><strong>SANs:</strong> ${escapeHtml(c.sans.join(', '))}</div>` : ''}
        </div>
      </div>

      <div class="cert-footer-actions">
        <button class="btn ${c.is_installed ? 'btn-secondary' : 'btn-primary'} btn-sm" onclick="installCertificate('${c.thumbprint}', '${escapeHtml(c.subject)}')">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
          <span>${c.is_installed ? 'Reinstall to MY' : 'Install to Windows MY'}</span>
        </button>
      </div>
    </div>
  `).join('');
}

// Install Certificate to Windows Store
window.installCertificate = async function(thumbprint, subject) {
  const cfg = getFormConfig();
  if (!cfg.addr) {
    showToast('Server address required', 'error');
    return;
  }

  showToast(`Installing certificate into Current User\\MY...`, 'info');
  try {
    if (window.backend && window.backend.InstallCertificate) {
      const msg = await window.backend.InstallCertificate(cfg, thumbprint);
      showToast(msg, 'success');
      // Refresh remote view and installed list
      await fetchRemoteCertificates();
      await loadInstalledCertificates();
      await loadDiagnostics();
    }
  } catch (err) {
    showToast(`Installation failed: ${err}`, 'error');
  }
};

// Load Installed Certificates from Manifest
async function loadInstalledCertificates() {
  try {
    if (window.backend && window.backend.ListInstalledCertificates) {
      const installed = await window.backend.ListInstalledCertificates();
      state.installedCerts = installed || [];
      elements.installedCountBadge.textContent = state.installedCerts.length;
      renderInstalledCertificates();
      populateTestSignCertificates();
    }
  } catch (err) {
    showToast(`Failed to load installed certificates: ${err}`, 'error');
  }
}

// Render Installed Certificates List
function renderInstalledCertificates() {
  const container = elements.installedCertsContainer;
  const filter = (elements.inputSearchInstalled.value || '').toLowerCase().trim();

  const filtered = state.installedCerts.filter(c => {
    if (!filter) return true;
    return (c.subject || '').toLowerCase().includes(filter) ||
           (c.thumbprint || '').toLowerCase().includes(filter);
  });

  elements.installedStatsText.textContent = `${filtered.length} installed binding(s)`;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
        <h3>No Certificate Bindings Found</h3>
        <p>No certificates are currently bound to Fred Proxy KSP.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(c => `
    <div class="installed-card">
      <div class="installed-main">
        <span class="installed-title">${escapeHtml(c.subject || 'Unknown Subject')}</span>
        <span class="installed-sub">${formatThumbprint(c.thumbprint)}</span>
        <span class="installed-meta">
          Installed: ${escapeHtml(c.installed_at || 'Unknown')} &bull; Provider: <code>${escapeHtml(c.provider)}</code>
          ${c.key_algorithm ? ` &bull; Key: <strong>${escapeHtml(c.key_algorithm)} ${c.key_size ? `${c.key_size}-bit` : ''}</strong>` : ''}
          ${c.is_tpm ? ' <span class="chip chip-info">TPM</span>' : ''}
        </span>
      </div>
      <div class="installed-actions">
        <button class="btn btn-secondary btn-sm" onclick="openTestSignPanel('${c.thumbprint}')" title="Test Sign with this certificate">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
          </svg>
          <span>Test Sign</span>
        </button>
        <button class="btn btn-danger btn-sm" onclick="promptUninstall('${c.thumbprint}', '${escapeHtml(c.subject)}')">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
          <span>Remove</span>
        </button>
      </div>
    </div>
  `).join('');
}

// Prompt for Uninstall
window.promptUninstall = function(thumbprint, subject) {
  showConfirmModal(
    'Uninstall Certificate Binding',
    `Are you sure you want to remove the certificate binding for <strong>${escapeHtml(subject)}</strong> (${formatThumbprint(thumbprint)}) from Windows MY store and the installed manifest?`,
    async () => {
      try {
        if (window.backend && window.backend.UninstallCertificate) {
          const msg = await window.backend.UninstallCertificate(thumbprint);
          showToast(msg, 'success');
          await loadInstalledCertificates();
          await fetchRemoteCertificates();
          await loadDiagnostics();
        }
      } catch (err) {
        showToast(`Removal failed: ${err}`, 'error');
      }
    }
  );
};

// ==========================================
// TEST SIGN DRAWER CONTROLLER
// ==========================================

// Open Test Sign Side Panel
window.openTestSignPanel = function(thumbprint = '') {
  if (!elements.testSignDrawer || !elements.testSignBackdrop) return;

  populateTestSignCertificates();

  if (thumbprint) {
    elements.tsCertSelect.value = thumbprint;
  } else if (!elements.tsCertSelect.value && state.installedCerts.length > 0) {
    elements.tsCertSelect.value = state.installedCerts[0].thumbprint;
  }

  onTestSignCertChanged();

  // Reset results / error boxes
  elements.tsResultContainer.classList.add('hidden');
  elements.tsErrorBox.classList.add('hidden');

  elements.testSignBackdrop.classList.remove('hidden');
  // Trigger transition
  requestAnimationFrame(() => {
    elements.testSignDrawer.classList.add('open');
  });
  state.testSign.isOpen = true;
};

// Close Test Sign Side Panel
window.closeTestSignPanel = function() {
  if (!elements.testSignDrawer || !elements.testSignBackdrop) return;
  elements.testSignDrawer.classList.remove('open');
  setTimeout(() => {
    elements.testSignBackdrop.classList.add('hidden');
  }, 250);
  state.testSign.isOpen = false;
};

// Populate Certificate Dropdown
function populateTestSignCertificates() {
  if (!elements.tsCertSelect) return;
  const currentVal = elements.tsCertSelect.value;
  const certs = state.installedCerts || [];

  if (certs.length === 0) {
    elements.tsCertSelect.innerHTML = '<option value="">-- No installed certificates found --</option>';
    return;
  }

  elements.tsCertSelect.innerHTML = `
    <option value="">-- Select an installed certificate --</option>
    ${certs.map(c => `
      <option value="${c.thumbprint}">
        ${escapeHtml(c.subject || 'Unknown')} [${c.key_algorithm || 'RSA'} ${c.key_size ? `${c.key_size}-bit` : ''}] (${formatThumbprint(c.thumbprint).substring(0, 14)}...)
      </option>
    `).join('')}
  `;

  if (currentVal && certs.some(c => c.thumbprint === currentVal)) {
    elements.tsCertSelect.value = currentVal;
  }
}

// Certificate Selection Changed
function onTestSignCertChanged() {
  const tp = elements.tsCertSelect.value;
  const cert = state.installedCerts.find(c => c.thumbprint === tp);

  if (!cert) {
    elements.tsCertPreview.classList.add('hidden');
    return;
  }

  elements.tsPreviewSubject.textContent = cert.subject || 'Unknown Subject';
  elements.tsPreviewKeytype.textContent = `${cert.key_algorithm || 'RSA'}${cert.key_size ? ` ${cert.key_size}-bit` : ''}${cert.is_tpm ? ' • TPM' : ''}`;
  elements.tsPreviewThumbprint.textContent = formatThumbprint(cert.thumbprint);
  elements.tsPreviewProvider.textContent = cert.provider || 'Fred Proxy Key Storage Provider';
  elements.tsCertPreview.classList.remove('hidden');

  const isECDSA = (cert.key_algorithm || '').toUpperCase().includes('ECDSA');
  if (isECDSA) {
    elements.tsPaddingGroup.classList.add('hidden');
    elements.tsEcdsaNote.classList.remove('hidden');
  } else {
    elements.tsPaddingGroup.classList.remove('hidden');
    elements.tsEcdsaNote.classList.add('hidden');
  }
}

// Payload Mode (Text vs Hex)
function setPayloadMode(mode) {
  state.testSign.mode = mode;
  if (mode === 'hex') {
    elements.btnModeText.classList.remove('active');
    elements.btnModeHex.classList.add('active');
    elements.tsInputTextGroup.classList.add('hidden');
    elements.tsInputHexGroup.classList.remove('hidden');
  } else {
    elements.btnModeHex.classList.remove('active');
    elements.btnModeText.classList.add('active');
    elements.tsInputHexGroup.classList.add('hidden');
    elements.tsInputTextGroup.classList.remove('hidden');
  }
  updateHexHint();
}

// Update Hex Length Hint
function updateHexHint() {
  const hash = elements.tsHashSelect.value;
  let bytes = 32;
  if (hash === 'SHA384') bytes = 48;
  if (hash === 'SHA512') bytes = 64;
  elements.tsHexHint.textContent = `Expected: ${bytes} bytes (${bytes * 2} hex characters) for ${hash}`;
}

// Switch Signature Output Format (Base64 vs Hex)
function setSignatureFormat(format) {
  state.testSign.sigFormat = format;
  if (format === 'hex') {
    elements.btnFmtBase64.classList.remove('active');
    elements.btnFmtHex.classList.add('active');
    if (state.testSign.lastResult) {
      elements.tsResultSignature.value = state.testSign.lastResult.signature_hex || '';
    }
  } else {
    elements.btnFmtHex.classList.remove('active');
    elements.btnFmtBase64.classList.add('active');
    if (state.testSign.lastResult) {
      elements.tsResultSignature.value = state.testSign.lastResult.signature_base64 || '';
    }
  }
}

// Execute Test Sign Request
async function executeTestSign() {
  const thumbprint = elements.tsCertSelect.value;
  if (!thumbprint) {
    showToast('Please select a certificate to test sign with', 'error');
    elements.tsCertSelect.focus();
    return;
  }

  const isHex = state.testSign.mode === 'hex';
  const message = isHex ? elements.tsInputHex.value.trim() : elements.tsInputMessage.value;
  if (!message) {
    showToast(isHex ? 'Please enter a hex digest' : 'Please enter a message to sign', 'error');
    if (isHex) elements.tsInputHex.focus();
    else elements.tsInputMessage.focus();
    return;
  }

  const req = {
    thumbprint: thumbprint,
    message: message,
    input_type: isHex ? 'hex_digest' : 'text',
    hash_algo: elements.tsHashSelect.value,
    padding: elements.tsPaddingSelect.value
  };

  // Set loading state
  elements.btnExecuteSign.disabled = true;
  elements.tsBtnLabel.textContent = 'Signing via KSP...';
  elements.tsResultContainer.classList.add('hidden');
  elements.tsErrorBox.classList.add('hidden');

  try {
    if (window.backend && window.backend.TestSign) {
      const res = await window.backend.TestSign(req);
      state.testSign.lastResult = res;

      // Populate results
      elements.tsResultDuration.textContent = `⚡ ${res.duration_ms} ms`;
      elements.tsResultStatus.textContent = 'Signature Verified';
      elements.tsResultAlg.textContent = res.signature_algorithm || 'CNG Signature';
      elements.tsResultHashname.textContent = res.hash_algorithm || 'SHA-256';
      elements.tsResultDigest.textContent = res.digest_hex || '';
      
      setSignatureFormat(state.testSign.sigFormat);

      elements.tsResultContainer.classList.remove('hidden');
      showToast(`Test signature generated successfully in ${res.duration_ms} ms!`, 'success');
    }
  } catch (err) {
    elements.tsErrorBox.textContent = `Signing Error: ${err}`;
    elements.tsErrorBox.classList.remove('hidden');
    showToast(`Test sign failed: ${err}`, 'error');
  } finally {
    elements.btnExecuteSign.disabled = false;
    elements.tsBtnLabel.textContent = 'Execute Test Sign';
  }
}

// Load Diagnostics Info
async function loadDiagnostics() {
  try {
    if (window.backend && window.backend.GetDiagnostics) {
      const diag = await window.backend.GetDiagnostics();
      if (diag) {
        elements.diagProvider.textContent = diag.provider_name || 'Fred Proxy Key Storage Provider';
        elements.diagDataDir.textContent = diag.data_dir || '';
        elements.diagConfigFile.textContent = diag.config_path || '';
        elements.diagManifestFile.textContent = diag.manifest_path || '';
        elements.diagKeyCount.textContent = `${diag.total_keys} keys active`;
      }
    }
  } catch (err) {
    console.error('Diagnostics error:', err);
  }
}

// Utilities
function formatThumbprint(tp) {
  if (!tp) return '';
  const clean = tp.replace(/\s+/g, '').toUpperCase();
  return clean.match(/.{1,4}/g)?.join(' ') || clean;
}

window.copyToClipboard = function(text, successMsg = 'Copied to clipboard!') {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(successMsg, 'info', 2000);
  }).catch(() => {
    showToast('Failed to copy', 'error');
  });
};

function showToast(message, type = 'info', duration = 4000) {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span>${escapeHtml(message)}</span>
  `;
  elements.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease-out';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

let confirmCallback = null;
function showConfirmModal(title, bodyHtml, onConfirm) {
  elements.modalTitle.textContent = title;
  elements.modalBody.innerHTML = bodyHtml;
  confirmCallback = onConfirm;
  elements.confirmModal.classList.remove('hidden');

  elements.btnModalConfirm.onclick = () => {
    hideConfirmModal();
    if (confirmCallback) confirmCallback();
  };
}

function hideConfirmModal() {
  elements.confirmModal.classList.add('hidden');
  confirmCallback = null;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

