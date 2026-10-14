/**
 * SENTINEL VAULT CORE // HUD TELEMETRY CLIENT
 * Architected by carlosguedes-dev
 * Zero Bloat | Pure Vanilla JS | Strict XSS-Free Safe DOM Rendering
 */

(function () {
  'use strict';

  // State Management
  const state = {
    token: sessionStorage.getItem('sentinel_token') || null,
    apiKey: null,
    user: null,
    secrets: [],
    activeFilter: 'all',
  };

  // Elements
  const statEngine = document.getElementById('statEngine');
  const statKdf = document.getElementById('statKdf');
  const statUptime = document.getElementById('statUptime');
  const statHealth = document.getElementById('statHealth');
  const statHealthDot = document.getElementById('statHealthDot');
  const authBadge = document.getElementById('authBadge');
  const authForm = document.getElementById('authForm');
  const btnLogin = document.getElementById('btnLogin');
  const btnGenKey = document.getElementById('btnGenKey');
  const vaultForm = document.getElementById('vaultForm');
  const inputValue = document.getElementById('inputValue');
  const entropyDisplay = document.getElementById('entropyDisplay');
  const secretsContainer = document.getElementById('secretsContainer');
  const auditLogStream = document.getElementById('auditLogStream');
  const btnRefresh = document.getElementById('btnRefresh');
  const decryptModal = document.getElementById('decryptModal');
  const modalTitle = document.getElementById('modalTitle');
  const revealedSecret = document.getElementById('revealedSecret');
  const btnCloseModal = document.getElementById('btnCloseModal');
  const btnCopySecret = document.getElementById('btnCopySecret');
  const toastContainer = document.getElementById('toastContainer');
  const filterButtons = document.querySelectorAll('.filter-btn');

  /* ==========================================================================
     1. SAFE DOM HELPERS (Zero innerHTML to prevent XSS)
     ========================================================================== */
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `hud-toast ${type}`;
    toast.textContent = message;

    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 4000);
  }

  function appendAuditLog(message, category = 'system') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${category}`;
    const time = new Date().toLocaleTimeString('pt-BR');
    entry.textContent = `[${time}] ${message}`;

    auditLogStream.appendChild(entry);
    auditLogStream.scrollTop = auditLogStream.scrollHeight;
  }

  /* ==========================================================================
     2. ENTROPY CALCULATION (Real-time feedback)
     ========================================================================== */
  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    let pool = 0;
    if (/[a-z]/.test(str)) pool += 26;
    if (/[A-Z]/.test(str)) pool += 26;
    if (/[0-9]/.test(str)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(str)) pool += 33;
    if (pool === 0) return 0;
    return Math.round(str.length * (Math.log(pool) / Math.log(2)));
  }

  inputValue.addEventListener('input', () => {
    const entropy = calculateEntropy(inputValue.value);
    entropyDisplay.textContent = `${entropy} bits`;
    if (entropy > 80) {
      entropyDisplay.className = 'text-emerald';
    } else if (entropy > 50) {
      entropyDisplay.className = 'text-cyan';
    } else {
      entropyDisplay.className = 'text-magenta';
    }
  });

  /* ==========================================================================
     3. TELEMETRY & HEALTH POLLING
     ========================================================================== */
  async function fetchTelemetry() {
    try {
      const res = await fetch('/api/v1/health');
      if (!res.ok) throw new Error('Health check failed');
      const data = await res.json();

      statEngine.textContent = data.securityEngine.cipherAlgorithm;
      statKdf.textContent = `${data.securityEngine.keyDerivation} (16k)`;
      statUptime.textContent = `${data.uptimeSeconds}s`;
      statHealth.textContent = data.status;
      statHealthDot.className = 'status-indicator live';
    } catch (e) {
      statHealth.textContent = 'OFFLINE';
      statHealthDot.className = 'status-indicator';
      statHealthDot.style.backgroundColor = 'var(--color-red)';
    }
  }

  /* ==========================================================================
     4. AUTHENTICATION CONTROLS
     ========================================================================== */
  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('inputUsername').value;
    const password = document.getElementById('inputPassword').value;

    btnLogin.disabled = true;
    btnLogin.textContent = 'VERIFYING...';

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Authentication rejected');
      }

      state.token = data.token;
      state.user = data.user;
      sessionStorage.setItem('sentinel_token', data.token);

      authBadge.textContent = `AUTHENTICATED: ${data.user.username} [${data.user.role}]`;
      authBadge.className = 'badge-tag authenticated';

      showToast(`Welcome ${data.user.username}. Session token established.`, 'success');
      appendAuditLog(`User '${data.user.username}' authenticated successfully.`, 'auth');

      await loadSecrets();
    } catch (err) {
      showToast(err.message, 'error');
      appendAuditLog(`Auth failure: ${err.message}`, 'error');
    } finally {
      btnLogin.disabled = false;
      btnLogin.textContent = 'AUTHENTICATE SESSION';
    }
  });

  btnGenKey.addEventListener('click', async () => {
    if (!state.token) {
      showToast('You must authenticate as ADMIN first to generate an API Key.', 'error');
      return;
    }

    try {
      const res = await fetch('/api/v1/auth/generate-api-key', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${state.token}`,
        },
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Key generation failed');

      state.apiKey = data.apiKey;
      showToast('API Key generated successfully! Copied to clipboard.', 'success');
      navigator.clipboard.writeText(data.apiKey);
      appendAuditLog(`New API Key generated: ${data.apiKey.substring(0, 10)}...`, 'auth');
    } catch (err) {
      showToast(err.message, 'error');
      appendAuditLog(`API key error: ${err.message}`, 'error');
    }
  });

  /* ==========================================================================
     5. VAULT OPERATIONS (Create, List, Decrypt, Delete)
     ========================================================================== */
  vaultForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.token) {
      showToast('Authentication required to store secrets.', 'error');
      return;
    }

    const keyName = document.getElementById('inputKeyName').value.trim();
    const plaintextValue = inputValue.value;
    const environment = document.getElementById('selectEnv').value;
    const rawTags = document.getElementById('inputTags').value;
    const tags = rawTags
      ? rawTags.split(',').map((t) => t.trim()).filter(Boolean)
      : [];

    try {
      const res = await fetch('/api/v1/vault/secrets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${state.token}`,
        },
        body: JSON.stringify({
          keyName,
          plaintextValue,
          environment,
          tags,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Encryption failed');

      showToast(`Secret '${keyName}' encrypted & committed to vault!`, 'success');
      appendAuditLog(`Secret '${keyName}' [${environment}] created with AES-256-GCM.`, 'system');

      // Clear input form safely
      document.getElementById('inputKeyName').value = '';
      inputValue.value = '';
      document.getElementById('inputTags').value = '';
      entropyDisplay.textContent = '0 bits';

      await loadSecrets();
    } catch (err) {
      showToast(err.message, 'error');
      appendAuditLog(`Vault error: ${err.message}`, 'error');
    }
  });

  async function loadSecrets() {
    if (!state.token) return;

    try {
      const url =
        state.activeFilter === 'all'
          ? '/api/v1/vault/secrets'
          : `/api/v1/vault/secrets?environment=${state.activeFilter}`;

      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${state.token}` },
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Failed to list secrets');

      state.secrets = data.secrets;
      renderSecretsList(data.secrets);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  function renderSecretsList(secrets) {
    // Clear list safely
    while (secretsContainer.firstChild) {
      secretsContainer.removeChild(secretsContainer.firstChild);
    }

    if (!secrets || secrets.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';
      const icon = document.createElement('div');
      icon.className = 'empty-icon';
      icon.textContent = '🛡️';
      const text = document.createElement('p');
      text.textContent = 'No secrets found for current filter. Ingest one on the left panel.';
      empty.appendChild(icon);
      empty.appendChild(text);
      secretsContainer.appendChild(empty);
      return;
    }

    secrets.forEach((s) => {
      const card = document.createElement('div');
      card.className = 'secret-card';

      const info = document.createElement('div');
      info.className = 'secret-info';

      const keyEl = document.createElement('div');
      keyEl.className = 'secret-key';
      keyEl.textContent = s.keyName;

      const metaEl = document.createElement('div');
      metaEl.className = 'secret-meta';

      const envSpan = document.createElement('span');
      envSpan.className = 'text-cyan';
      envSpan.textContent = `[${s.environment.toUpperCase()}]`;

      const accessesSpan = document.createElement('span');
      accessesSpan.textContent = `Accesses: ${s.accessCount}`;

      const dateSpan = document.createElement('span');
      dateSpan.textContent = new Date(s.createdAt).toLocaleDateString('pt-BR');

      metaEl.appendChild(envSpan);
      metaEl.appendChild(accessesSpan);
      metaEl.appendChild(dateSpan);

      info.appendChild(keyEl);
      info.appendChild(metaEl);

      const actions = document.createElement('div');
      actions.className = 'secret-actions';

      const btnDecrypt = document.createElement('button');
      btnDecrypt.className = 'hud-btn-mini';
      btnDecrypt.textContent = 'DECRYPT';
      btnDecrypt.addEventListener('click', () => decryptSecret(s.id, s.keyName));

      const btnDelete = document.createElement('button');
      btnDelete.className = 'hud-btn-mini';
      btnDelete.style.borderColor = 'var(--color-red)';
      btnDelete.style.color = 'var(--color-red)';
      btnDelete.textContent = 'PURGE';
      btnDelete.addEventListener('click', () => purgeSecret(s.id, s.keyName));

      actions.appendChild(btnDecrypt);
      actions.appendChild(btnDelete);

      card.appendChild(info);
      card.appendChild(actions);
      secretsContainer.appendChild(card);
    });
  }

  async function decryptSecret(id, keyName) {
    try {
      const res = await fetch(`/api/v1/vault/secrets/${id}/decrypt`, {
        headers: { Authorization: `Bearer ${state.token}` },
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Decryption failed');

      modalTitle.textContent = `AUTHENTICATED DECRYPTION: ${keyName}`;
      revealedSecret.textContent = data.plaintextValue;
      decryptModal.className = 'hud-modal active';

      appendAuditLog(`Audited decryption for key '${keyName}' by user.`, 'auth');
    } catch (err) {
      showToast(err.message, 'error');
      appendAuditLog(`Decryption failure for '${keyName}': ${err.message}`, 'error');
    }
  }

  async function purgeSecret(id, keyName) {
    if (!confirm(`Are you sure you want to purge secret '${keyName}' from the vault?`)) {
      return;
    }

    try {
      const res = await fetch(`/api/v1/vault/secrets/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${state.token}` },
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Deletion failed');

      showToast(`Secret '${keyName}' purged.`, 'success');
      appendAuditLog(`Secret '${keyName}' purged from vault.`, 'system');
      await loadSecrets();
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  /* ==========================================================================
     6. UI CONTROLS & MODAL LISTENERS
     ========================================================================== */
  btnCloseModal.addEventListener('click', () => {
    decryptModal.className = 'hud-modal';
    revealedSecret.textContent = '...';
  });

  btnCopySecret.addEventListener('click', () => {
    navigator.clipboard.writeText(revealedSecret.textContent);
    showToast('Secret copied to clipboard!', 'success');
  });

  btnRefresh.addEventListener('click', loadSecrets);

  filterButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      filterButtons.forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      state.activeFilter = btn.getAttribute('data-env');
      loadSecrets();
    });
  });

  // Initialization
  fetchTelemetry();
  setInterval(fetchTelemetry, 5000);

  if (state.token) {
    authBadge.textContent = 'SESSION RESTORED';
    authBadge.className = 'badge-tag authenticated';
    loadSecrets();
  }
})();
