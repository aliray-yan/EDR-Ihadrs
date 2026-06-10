/* ========================================================
   IHADRS Web Dashboard — dashboard.js
   Polls the IHADRS REST API and drives all UI updates.
   No external dependencies — plain ES2022.
   ======================================================== */

'use strict';

// ── CONFIG ─────────────────────────────────────────────────
const DEFAULT_URL      = 'http://127.0.0.1:8765';
const DEFAULT_INTERVAL = 3000;
const DEFAULT_THEME    = 'dark';
const WORKFLOW_STATUSES = ['new', 'acknowledged', 'investigating', 'remediated', 'false_positive'];

let cfg = {
  url:      localStorage.getItem('ihadrs_url')      || DEFAULT_URL,
  token:    localStorage.getItem('ihadrs_token')    || '',
  interval: parseInt(localStorage.getItem('ihadrs_interval') || DEFAULT_INTERVAL),
  theme:    localStorage.getItem('ihadrs_theme')    || DEFAULT_THEME,
};

// ── STATE ───────────────────────────────────────────────────
let state = {
  connected: false,
  threats:   [],
  events:    [],
  rules:     [],
  stats:     {},
  status:    {},
  selectedThreatIdx: -1,
  secureops: {},
  workflow: loadWorkflowState(),
  selectedThreatIds: new Set(),
  filteredThreats: [],
};

let pollTimer = null;

// ── DOM HELPERS ─────────────────────────────────────────────
const $  = id => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls)  e.className   = cls;
  if (html) e.innerHTML   = html;
  return e;
};
const esc = s => String(s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const jsArg = value => JSON.stringify(String(value || ''));

function applyTheme(theme) {
  cfg.theme = theme === 'light' ? 'light' : 'dark';
  document.documentElement.dataset.theme = cfg.theme;
  localStorage.setItem('ihadrs_theme', cfg.theme);
  const btn = $('theme-toggle');
  if (btn) btn.textContent = cfg.theme === 'light' ? 'Dark' : 'Light';
}

function toggleTheme() {
  applyTheme(cfg.theme === 'light' ? 'dark' : 'light');
}

applyTheme(cfg.theme);

// ── CLOCK ───────────────────────────────────────────────────
function tickClock() {
  const now = new Date();
  $('clock').textContent = now.toLocaleTimeString();
}
setInterval(tickClock, 1000);
tickClock();

// ── SETTINGS ───────────────────────────────────────────────
function openSettings() {
  $('cfg-url').value      = cfg.url;
  $('cfg-token').value    = cfg.token;
  $('cfg-interval').value = cfg.interval;
  $('settings-drawer').classList.add('open');
  $('drawer-overlay').classList.remove('hidden');
  // Clear previous result message
  const res = $('cfg-result');
  if (res) { res.className = 'cfg-result'; res.textContent = ''; }
  loadSecureOpsSettings();
}
function closeSettings() {
  $('settings-drawer').classList.remove('open');
  $('drawer-overlay').classList.add('hidden');
}
function saveSettings() {
  cfg.url      = $('cfg-url').value.trim()   || DEFAULT_URL;
  cfg.token    = $('cfg-token').value.trim();
  cfg.interval = parseInt($('cfg-interval').value) || DEFAULT_INTERVAL;
  localStorage.setItem('ihadrs_url',      cfg.url);
  localStorage.setItem('ihadrs_token',    cfg.token);
  localStorage.setItem('ihadrs_interval', cfg.interval);
  closeSettings();
  restartPolling();
  toast('Settings saved. Reconnecting...');
}
async function testConnection() {
  const res = $('cfg-result');
  res.className = 'cfg-result';
  res.textContent = 'Testing…';
  try {
    const r = await fetch(`${$('cfg-url').value.trim() || DEFAULT_URL}/healthz`,
                          { signal: AbortSignal.timeout(3000) });
    const d = await r.json();
    res.className   = 'cfg-result ok';
    res.textContent = `Connected - version ${d.version || '?'}`;
  } catch(e) {
    res.className   = 'cfg-result err';
    res.textContent = e.message;
  }
}
async function loadSecureOpsSettings() {
  const res = $('soc-result');
  try {
    const data = await apiFetch('/api/v1/secureops/settings');
    state.secureops = data;
    $('soc-enabled').checked = !!data.enabled;
    $('soc-base-url').value = data.api_base_url || 'http://127.0.0.1:8000/api/v1';
    $('soc-allow-http').checked = data.allow_http_lab !== false;
    $('soc-ingest-key').value = '';
    $('soc-ingest-key').placeholder = data.key_configured
      ? 'Saved with Windows DPAPI'
      : 'Paste SecureOps EDR ingest key';
    renderSecureOpsStatus(data);
    if (res) { res.className = 'cfg-result'; res.textContent = ''; }
  } catch(e) {
    if (res) {
      res.className = 'cfg-result err';
      res.textContent = `Could not load SecureOps settings: ${e.message}`;
    }
  }
}

async function saveSecureOpsSettings() {
  const res = $('soc-result');
  res.className = 'cfg-result';
  res.textContent = 'Saving...';
  const ingestKey = $('soc-ingest-key').value.trim();
  const body = {
    enabled: $('soc-enabled').checked,
    api_base_url: $('soc-base-url').value.trim(),
    allow_http_lab: $('soc-allow-http').checked,
  };
  if (ingestKey) body.ingest_key = ingestKey;

  try {
    const data = await apiFetch('/api/v1/secureops/settings', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    $('soc-ingest-key').value = '';
    state.secureops = data;
    renderSecureOpsStatus(data);
    res.className = 'cfg-result ok';
    res.textContent = 'SecureOps settings saved.';
    toast('SecureOps settings saved.');
  } catch(e) {
    res.className = 'cfg-result err';
    res.textContent = e.message;
  }
}

async function testSecureOpsConnection() {
  const res = $('soc-result');
  res.className = 'cfg-result';
  res.textContent = 'Testing SecureOps...';
  const ingestKey = $('soc-ingest-key').value.trim();
  const body = {
    api_base_url: $('soc-base-url').value.trim(),
    allow_http_lab: $('soc-allow-http').checked,
  };
  if (ingestKey) body.ingest_key = ingestKey;

  try {
    const data = await apiFetch('/api/v1/secureops/test', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (data.success) {
      res.className = 'cfg-result ok';
      res.textContent = `Connected. Source: ${data.response?.source || 'EDR'}`;
    } else {
      res.className = 'cfg-result err';
      res.textContent = data.error || `HTTP ${data.status_code}`;
    }
  } catch(e) {
    res.className = 'cfg-result err';
    res.textContent = e.message;
  }
}

async function refreshSecureOpsStatus() {
  try {
    const data = await apiFetch('/api/v1/secureops/status');
    state.secureops = data;
    renderSecureOpsStatus(data);
  } catch(e) {
    state.secureops = { last_error: e.message };
    renderSecureOpsStatus(state.secureops);
  }
}

function renderSecureOpsStatus(data) {
  if (!$('soc-queue-depth')) return;
  $('soc-queue-depth').textContent = data.queue_depth ?? '0';
  $('soc-high-critical').textContent = data.critical_high_queued ?? '0';
  $('soc-last-upload').textContent = data.last_successful_upload
    ? fmtTimeFull(data.last_successful_upload)
    : 'Never';
  $('soc-last-error').textContent = data.last_error || (data.bad_ingest_key ? 'Bad ingest key' : 'None');
  const keyState = data.key_configured ? 'Key saved' : 'No key';
  const exportState = data.enabled ? 'Enabled' : 'Disabled';
  $('soc-state').textContent = `${exportState} / ${keyState}`;
}

$('settings-toggle').onclick = openSettings;
$('theme-toggle').onclick = toggleTheme;
window.toggleTheme = toggleTheme;
window.openSettings    = openSettings;
window.closeSettings   = closeSettings;
window.saveSettings    = saveSettings;
window.testConnection  = testConnection;
window.loadSecureOpsSettings = loadSecureOpsSettings;
window.saveSecureOpsSettings = saveSecureOpsSettings;
window.testSecureOpsConnection = testSecureOpsConnection;

// ── TABS ────────────────────────────────────────────────────
function switchTab(name) {
  $$('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));
  if (name === 'rules' && state.rules.length === 0) fetchRules();
}
$$('.tab-btn').forEach(btn => btn.onclick = () => switchTab(btn.dataset.tab));
if ($('select-all-alerts')) {
  $('select-all-alerts').onchange = e => toggleAllAlerts(e.target.checked);
}
window.switchTab = switchTab;

// ── FETCH HELPERS ───────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (cfg.token) headers['X-IHADRS-Token'] = cfg.token;
  const r = await fetch(`${cfg.url}${path}`, {
    ...options,
    headers: { ...headers, ...(options.headers || {}) },
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── POLLING ─────────────────────────────────────────────────
async function poll() {
  try {
    // Status
    const status = await apiFetch('/api/v1/status');
    state.status = status;
    updateStatus(status);

    // Threats
    const tData = await apiFetch('/api/v1/threats?limit=100');
    state.threats = tData.threats || [];
    updateAlertBadge();
    renderRecentThreats();
    filterAlerts();

    // Stats
    const stats = await apiFetch('/api/v1/stats?hours=24');
    state.stats = stats;
    updateMetrics(stats);
    renderCategoryBars(stats);

    // Also refresh events tab if currently visible
    if (document.getElementById('tab-events').classList.contains('active')) {
      fetchEvents();
    }

    // SecureOps status is lightweight and keeps the settings drawer live.
    refreshSecureOpsStatus();

    if (!state.connected) {
      state.connected = true;
      setConnectionState('connected', 'Protected');
    }
  } catch(err) {
    state.connected = false;
    setConnectionState('error', `Disconnected - ${err.message}`);
  }
}

async function fetchRules() {
  try {
    const d = await apiFetch('/api/v1/rules');
    state.rules = d.rules || [];
    renderRules();
  } catch(e) {
    renderTableError('rules-table', 6, 'Could not load rules: ' + e.message);
  }
}

function restartPolling() {
  if (pollTimer) clearInterval(pollTimer);
  poll();
  pollTimer = setInterval(poll, cfg.interval);
}

// ── CONNECTION STATE ─────────────────────────────────────────
function setConnectionState(cls, text) {
  const pill = $('connection-status');
  pill.className = `status-pill ${cls}`;
  pill.querySelector('.status-text').textContent = text;
}

// ── STATUS UPDATE ────────────────────────────────────────────
function updateStatus(status) {
  const ver = status.version || '?';
  $('version-badge').textContent = `v${ver}`;

  const det = status.detection || {};
  $('m-eps').textContent   = (det.events_per_second || 0).toFixed(2);
  $('m-rules').textContent = det.rule_count || '-';

  const monitors = status.monitors || [];
  const tbody = $('monitor-table').querySelector('tbody');
  if (!monitors.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">No monitors running.</td></tr>';
    return;
  }
  tbody.innerHTML = monitors.map(m => `
    <tr>
      <td>${esc(m.name || '')}</td>
      <td><span class="severity-chip ${m.running ? 'severity-low' : 'severity-critical'}">${m.running ? 'RUNNING' : 'STOPPED'}</span></td>
      <td>${(m.events_published || 0).toLocaleString()}</td>
      <td>${m.errors || 0}</td>
    </tr>`).join('');
}

// ── METRIC CARDS ─────────────────────────────────────────────
function updateMetrics(stats) {
  const sev = stats.by_severity || {};
  $('m-critical').textContent = sev.CRITICAL || 0;
  $('m-high').textContent     = sev.HIGH     || 0;
  $('m-medium').textContent   = sev.MEDIUM   || 0;
  $('m-low').textContent      = sev.LOW      || 0;
}

// ── ALERT BADGE ───────────────────────────────────────────────
function updateAlertBadge() {
  const active = state.threats.filter(t => !isFalsePositive(t)).length;
  const badge = $('alert-badge');
  badge.textContent = active > 0 ? active : '';
}

// ── RECENT THREATS (overview) ────────────────────────────────
function renderRecentThreats() {
  const tbody = $('recent-threats-table').querySelector('tbody');
  const recent = state.threats.slice(0, 10);
  if (!recent.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No threats detected yet.</td></tr>';
    return;
  }
  tbody.innerHTML = recent.map(t => `
    <tr onclick="switchTab('alerts')" style="cursor:pointer">
      <td>${fmtTime(t.timestamp)}</td>
      <td>${severityChip(t.severity)}</td>
      <td>${esc(t.attack_category || '-')}</td>
      <td>${esc((t.affected_resource || '').substring(0,40))}</td>
      <td>${((t.confidence || 0) * 100).toFixed(0)}%</td>
    </tr>`).join('');
}

// ── CATEGORY BARS (overview) ─────────────────────────────────
function renderCategoryBars(stats) {
  const byCat = stats.by_category || {};
  const entries = Object.entries(byCat).sort((a,b) => b[1]-a[1]);
  const max = Math.max(...entries.map(e=>e[1]), 1);
  const container = $('category-bars');
  if (!entries.length) {
    container.innerHTML = '<p style="color:var(--muted);padding:16px;text-align:center">No data yet.</p>';
    return;
  }
  container.innerHTML = entries.map(([cat, cnt]) => `
    <div class="cat-bar-row">
      <div class="cat-bar-label" title="${esc(cat)}">${esc(cat)}</div>
      <div class="cat-bar-track">
        <div class="cat-bar-fill" style="width:${(cnt/max*100).toFixed(1)}%"></div>
      </div>
      <div class="cat-bar-count">${cnt}</div>
    </div>`).join('');
}

// ── ALERTS TAB ────────────────────────────────────────────────
function loadWorkflowState() {
  try {
    return JSON.parse(localStorage.getItem('ihadrs_alert_workflow') || '{}');
  } catch {
    return {};
  }
}

function saveWorkflowState() {
  localStorage.setItem('ihadrs_alert_workflow', JSON.stringify(state.workflow));
}

function threatId(t) {
  return String(t?.threat_id || t?.alert_id || '');
}

function getWorkflow(id) {
  if (!id) return { status: 'new', notes: [] };
  if (!state.workflow[id]) {
    state.workflow[id] = { status: 'new', notes: [] };
  }
  if (!WORKFLOW_STATUSES.includes(state.workflow[id].status)) {
    state.workflow[id].status = 'new';
  }
  if (!Array.isArray(state.workflow[id].notes)) {
    state.workflow[id].notes = [];
  }
  return state.workflow[id];
}

function isFalsePositive(t) {
  const id = threatId(t);
  return !!t.false_positive?.marked || getWorkflow(id).status === 'false_positive';
}

function workflowLabel(status) {
  return {
    new: 'NEW',
    acknowledged: 'ACKNOWLEDGED',
    investigating: 'INVESTIGATING',
    remediated: 'REMEDIATED',
    false_positive: 'FALSE POSITIVE',
  }[status] || 'NEW';
}

function workflowChip(status) {
  const normalized = WORKFLOW_STATUSES.includes(status) ? status : 'new';
  return `<span class="workflow-chip workflow-${normalized}">${workflowLabel(normalized)}</span>`;
}

function workflowOptions(selected) {
  return WORKFLOW_STATUSES.map(status =>
    `<option value="${status}" ${status === selected ? 'selected' : ''}>${workflowLabel(status)}</option>`
  ).join('');
}

function setAlertStatus(id, status) {
  if (!id || !WORKFLOW_STATUSES.includes(status)) return;
  const workflow = getWorkflow(id);
  workflow.status = status;
  workflow.updated_at = new Date().toISOString();
  saveWorkflowState();
  filterAlerts();
  const selected = state.threats.find(t => threatId(t) === id);
  if (selected) renderAlertDetail(selected);
  toast(`Alert marked ${workflowLabel(status).toLowerCase()}.`);
}

function toggleAlertSelection(id, checked) {
  if (!id) return;
  if (checked) state.selectedThreatIds.add(id);
  else state.selectedThreatIds.delete(id);
  updateAlertSelectionUi();
}

function toggleAllAlerts(checked) {
  state.filteredThreats.forEach(t => {
    const id = threatId(t);
    if (!id) return;
    if (checked) state.selectedThreatIds.add(id);
    else state.selectedThreatIds.delete(id);
  });
  filterAlerts();
}

function updateAlertSelectionUi() {
  const count = state.selectedThreatIds.size;
  const total = state.filteredThreats.length;
  const footer = $('alerts-count');
  if (footer) footer.textContent = `${total} alert(s) | ${count} selected`;
  const all = $('select-all-alerts');
  if (all) {
    all.checked = total > 0 && state.filteredThreats.every(t => state.selectedThreatIds.has(threatId(t)));
    all.indeterminate = count > 0 && !all.checked;
  }
}

function bulkSetStatus(status) {
  if (!WORKFLOW_STATUSES.includes(status)) return;
  if (!state.selectedThreatIds.size) {
    toast('Select at least one alert first.');
    return;
  }
  state.selectedThreatIds.forEach(id => {
    const workflow = getWorkflow(id);
    workflow.status = status;
    workflow.updated_at = new Date().toISOString();
  });
  saveWorkflowState();
  filterAlerts();
  toast(`${state.selectedThreatIds.size} alert(s) updated.`);
}

function renderNotes(id) {
  const notes = getWorkflow(id).notes;
  if (!notes.length) {
    return '<div class="notes-list"><div class="note-item"><div class="note-body" style="color:var(--muted)">No analyst notes yet.</div></div></div>';
  }
  return `<div class="notes-list">${notes.map(note => `
    <div class="note-item">
      <div class="note-meta">${fmtTimeFull(note.created_at)}</div>
      <div class="note-body">${esc(note.text)}</div>
    </div>`).join('')}</div>`;
}

function addAlertNote(id) {
  const input = $('alert-note-input');
  const text = (input?.value || '').trim();
  if (!id || !text) {
    toast('Write a note first.');
    return;
  }
  const workflow = getWorkflow(id);
  workflow.notes.unshift({ text, created_at: new Date().toISOString() });
  workflow.updated_at = new Date().toISOString();
  saveWorkflowState();
  const selected = state.threats.find(t => threatId(t) === id);
  if (selected) renderAlertDetail(selected);
  toast('Note added.');
}

window.setAlertStatus = setAlertStatus;
window.toggleAlertSelection = toggleAlertSelection;
window.toggleAllAlerts = toggleAllAlerts;
window.bulkSetStatus = bulkSetStatus;
window.addAlertNote = addAlertNote;

function filterAlerts() {
  const q      = $('alert-search').value.toLowerCase();
  const sevF   = $('alert-sev-filter').value;
  const statusF = $('alert-status-filter').value;
  const showFP = $('show-fp').checked;

  const filtered = state.threats.filter(t => {
    const id = threatId(t);
    const workflow = getWorkflow(id);
    if (!showFP && isFalsePositive(t)) return false;
    if (sevF && t.severity !== sevF) return false;
    if (statusF && workflow.status !== statusF) return false;
    if (q) {
      const hay = [t.summary, t.attack_category, t.affected_resource,
                   t.severity, t.threat_id, workflow.status].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  state.filteredThreats = filtered;

  const tbody = $('alerts-table').querySelector('tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No matching alerts.</td></tr>';
    $('alerts-count').textContent = '0 alerts';
    updateAlertSelectionUi();
    return;
  }
  tbody.innerHTML = filtered.map((t, i) => `
    <tr data-idx="${i}" class="${state.selectedThreatIdx === i ? 'selected' : ''}"
        onclick="selectAlert(${i})">
      <td><input class="row-select" type="checkbox" ${state.selectedThreatIds.has(threatId(t)) ? 'checked' : ''} onclick="event.stopPropagation()" onchange="toggleAlertSelection(${jsArg(threatId(t))}, this.checked)" /></td>
      <td>${fmtTime(t.timestamp)}</td>
      <td>${severityChip(t.severity)}</td>
      <td>${workflowChip(getWorkflow(threatId(t)).status)}</td>
      <td>${esc(t.attack_category || '-')}</td>
      <td>${esc((t.affected_resource || '').substring(0,45))}</td>
    </tr>`).join('');

  updateAlertSelectionUi();

  // Re-apply selection
  if (state.selectedThreatIdx >= 0 && state.selectedThreatIdx < filtered.length) {
    renderAlertDetail(filtered[state.selectedThreatIdx]);
  }
}
window.filterAlerts = filterAlerts;

function selectAlert(idx) {
  state.selectedThreatIdx = idx;
  $$('#alerts-table tbody tr').forEach((r, i) => r.classList.toggle('selected', i === idx));
  const filtered = getFilteredAlerts();
  if (filtered[idx]) renderAlertDetail(filtered[idx]);
}
window.selectAlert = selectAlert;

function getFilteredAlerts() {
  const q    = $('alert-search').value.toLowerCase();
  const sevF = $('alert-sev-filter').value;
  const statusF = $('alert-status-filter').value;
  const showFP = $('show-fp').checked;
  return state.threats.filter(t => {
    const id = threatId(t);
    const workflow = getWorkflow(id);
    if (!showFP && isFalsePositive(t)) return false;
    if (sevF && t.severity !== sevF) return false;
    if (statusF && workflow.status !== statusF) return false;
    if (q) {
      const hay = [t.summary, t.attack_category, t.affected_resource,
                   t.severity, t.threat_id, workflow.status].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderAlertDetail(t) {
  const id      = threatId(t);
  const flow    = getWorkflow(id);
  const mitre   = t.mitre || {};
  const expl    = t.explanation || {};
  const steps   = t.remediation || [];
  const pc      = t.process_context;

  const techniques = (mitre.techniques || [])
    .map((id, i) => `<span class="mitre-pill">${esc(id)} ${esc((mitre.technique_names||[])[i]||'')}</span>`)
    .join('');

  const remHtml = steps.map(s => `
    <div class="remediation-step">
      <span class="step-num">${s.step||'•'}</span>
      <span>${esc(s.description||'')}</span>
      ${s.command ? `<code class="step-cmd">${esc(s.command)}</code>` : ''}
    </div>`).join('') || '<p style="color:var(--muted)">No steps defined.</p>';

  const procHtml = pc ? `
    <div class="detail-section">
      <h4>Process Context</h4>
      <pre>Name:    ${esc(pc.name||'')} (PID ${pc.pid||'?'})
Parent:  ${esc(pc.parent_name||'')} (PID ${pc.parent_pid||'?'})
Command: ${esc((pc.command_line||'').substring(0,120))}
User:    ${esc(pc.username||'')}
Elevated: ${pc.is_elevated ? 'Yes' : 'No'}${pc.sha256 ? '\nSHA256:  '+esc(pc.sha256) : ''}</pre>
    </div>` : '';

  $('alert-detail').innerHTML = `
    <div class="detail-panel">
      <div class="detail-title sev-${esc(t.severity||'')}">
        ${severityChip(t.severity)} ${esc(t.attack_category||'-')}
      </div>
      <div class="detail-meta">
        ID: ${esc((t.threat_id||'').substring(0,16))}...  |
        Confidence: ${((t.confidence||0)*100).toFixed(0)}%  |
        ${fmtTimeFull(t.timestamp)}  |
        Host: ${esc(t.hostname||'unknown')}
      </div>

      <div class="detail-section">
        <h4>What Happened</h4>
        <p>${esc(expl.user || t.summary || '—')}</p>
      </div>

      <div class="detail-section">
        <h4>Operator Workflow</h4>
        <div class="detail-control-row">
          <select class="filter-select workflow-select" onchange="setAlertStatus(${jsArg(id)}, this.value)">
            ${workflowOptions(flow.status)}
          </select>
          ${workflowChip(flow.status)}
        </div>
      </div>

      <div class="detail-section">
        <h4>Technical Details</h4>
        <pre>${esc(expl.technical||'—')}</pre>
      </div>

      ${procHtml}

      <div class="detail-section">
        <h4>MITRE ATT&CK</h4>
        <div>${techniques || '<span style="color:var(--muted)">None mapped.</span>'}</div>
      </div>

      <div class="detail-section">
        <h4>Recommended Actions</h4>
        ${remHtml}
      </div>

      <div class="detail-section">
        <h4>Analyst Notes</h4>
        <textarea id="alert-note-input" class="note-input" placeholder="Add investigation notes, triage context, or next steps..."></textarea>
        <div class="detail-actions" style="border-top:0;padding-top:8px">
          <button class="btn btn-xs" onclick="addAlertNote(${jsArg(id)})">Add Note</button>
        </div>
        ${renderNotes(id)}
      </div>

      <div class="detail-actions">
        <button class="btn btn-xs btn-danger" onclick="markFP(${jsArg(id)})">Mark False Positive</button>
        <button class="btn btn-xs" onclick="setAlertStatus(${jsArg(id)}, 'acknowledged')">Acknowledge</button>
        <button class="btn btn-xs" onclick="setAlertStatus(${jsArg(id)}, 'investigating')">Investigate</button>
        <button class="btn btn-xs" onclick="setAlertStatus(${jsArg(id)}, 'remediated')">Remediate</button>
        <button class="btn btn-xs" onclick="exportSingle(${jsArg(id)})">Export</button>
        ${pc?.sha256 ? `<button class="btn btn-xs" onclick="virusTotal(${jsArg(pc.sha256)})">VirusTotal</button>` : ''}
      </div>
    </div>`;
}

async function markFP(threatId) {
  if (!confirm('Mark this threat as a false positive?')) return;
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (cfg.token) headers['X-IHADRS-Token'] = cfg.token;
    await fetch(`${cfg.url}/api/v1/threats/${threatId}/fp`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ marked_by: 'web_dashboard', reason: 'Marked via web UI' }),
    });
    setAlertStatus(threatId, 'false_positive');
    toast('Marked as false positive.');
    poll();
  } catch(e) { toast('Error: ' + e.message); }
}
window.markFP = markFP;

function virusTotal(sha256) {
  window.open(`https://www.virustotal.com/gui/file/${sha256}`, '_blank');
}
window.virusTotal = virusTotal;

function exportSingle(threatId) {
  const t = state.threats.find(x => x.threat_id === threatId);
  if (!t) return;
  downloadJSON([withWorkflow(t)], `threat_${threatId.substring(0,8)}.json`);
}
window.exportSingle = exportSingle;

function withWorkflow(t) {
  const id = threatId(t);
  return {
    ...t,
    operator_workflow: getWorkflow(id),
  };
}

function exportSelectedAlerts() {
  const selected = state.threats
    .filter(t => state.selectedThreatIds.has(threatId(t)))
    .map(withWorkflow);
  if (!selected.length) {
    toast('Select at least one alert first.');
    return;
  }
  downloadJSON(selected, 'ihadrs_selected_alerts.json');
}
window.exportSelectedAlerts = exportSelectedAlerts;

function exportAlerts() {
  downloadJSON(getFilteredAlerts().map(withWorkflow), 'ihadrs_alerts.json');
}
window.exportAlerts = exportAlerts;

// ── EVENTS TAB ───────────────────────────────────────────────
async function fetchEvents() {
  try {
    const d = await apiFetch('/api/v1/events?limit=200');
    state.events = d.events || [];
    filterEvents();
  } catch(e) {
    renderTableError('events-table', 4, 'Could not load events: ' + e.message);
  }
}

function filterEvents() {
  const q = $('event-search').value.toLowerCase();
  const filtered = q
    ? state.events.filter(e => JSON.stringify(e).toLowerCase().includes(q))
    : state.events;

  const tbody = $('events-table').querySelector('tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty">No events.</td></tr>';
    $('events-count').textContent = '0 events';
    return;
  }
  tbody.innerHTML = filtered.slice(0, 200).map(e => {
    const pl = e.payload || {};
    const det = typeof pl === 'object'
      ? Object.entries(pl).slice(0,3).map(([k,v])=>`${k}=${v}`).join(' | ')
      : String(pl).substring(0,80);
    return `<tr>
      <td>${fmtTimeFull(e.timestamp)}</td>
      <td>${esc(e.event_type||'')}</td>
      <td>${esc(e.source||'')}</td>
      <td>${esc(det)}</td>
    </tr>`;
  }).join('');
  $('events-count').textContent = `${filtered.length} event(s)`;
}
window.filterEvents = filterEvents;

function clearEvents() { state.events = []; filterEvents(); }
window.clearEvents = clearEvents;

function exportEvents() { downloadJSON(state.events, 'ihadrs_events.json'); }
window.exportEvents = exportEvents;

// ── RULES TAB ────────────────────────────────────────────────
function renderRules() {
  const q = ($('rule-search')?.value || '').toLowerCase();
  const filtered = q
    ? state.rules.filter(r => (r.rule_id+r.name+r.attack_category).toLowerCase().includes(q))
    : state.rules;

  $('rules-count').textContent = `${filtered.length} / ${state.rules.length} rules`;
  const tbody = $('rules-table').querySelector('tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No rules.</td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(r => `
    <tr>
      <td><code>${esc(r.rule_id||'')}</code></td>
      <td>${esc(r.name||'')}</td>
      <td>${severityChip(r.severity)}</td>
      <td>${esc(r.attack_category||'-')}</td>
      <td>${(r.mitre_techniques||[]).map(t=>`<span class="mitre-pill">${esc(t)}</span>`).join('')}</td>
      <td><span class="severity-chip ${r.enabled ? 'severity-low' : 'severity-info'}">${r.enabled ? 'ENABLED' : 'DISABLED'}</span></td>
    </tr>`).join('');
}

function filterRules() { renderRules(); }
window.filterRules = filterRules;

// ── UTILITIES ─────────────────────────────────────────────────
function severityChip(sev) {
  const normalized = String(sev || 'INFO').toUpperCase();
  const className = {
    CRITICAL: 'severity-critical',
    HIGH: 'severity-high',
    MEDIUM: 'severity-medium',
    LOW: 'severity-low',
  }[normalized] || 'severity-info';
  return `<span class="severity-chip ${className}">${esc(normalized)}</span>`;
}

function fmtTime(ts) {
  if (!ts) return '-';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-GB', { month:'2-digit', day:'2-digit',
      hour:'2-digit', minute:'2-digit', hour12: false });
  } catch { return ts.substring(0,16); }
}

function fmtTimeFull(ts) {
  if (!ts) return '-';
  try { return new Date(ts).toLocaleString(); }
  catch { return ts; }
}

function renderTableError(tableId, cols, msg) {
  const tbody = $(tableId)?.querySelector('tbody');
  if (tbody) tbody.innerHTML = `<tr><td colspan="${cols}" class="empty">${esc(msg)}</td></tr>`;
}

function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function toast(msg, duration = 3000) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.add('hidden'), duration);
}

// ── BOOT ─────────────────────────────────────────────────────
restartPolling();
