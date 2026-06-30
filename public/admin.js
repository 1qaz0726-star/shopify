// admin.js — Consentry admin dashboard

const SCANNER_URL = 'https://shopify-0c9l.onrender.com/';

// DOM refs — auth
const loginView    = document.getElementById('login-view');
const dashView     = document.getElementById('dashboard-view');
const loginForm    = document.getElementById('login-form');
const loginError   = document.getElementById('login-error');
const pwdInput     = document.getElementById('pwd-input');
const logoutBtn    = document.getElementById('logout-btn');

// DOM refs — pipeline
const pipelineStatus = document.getElementById('pipeline-status');
const statTotal      = document.getElementById('stat-total');
const statDone       = document.getElementById('stat-done');
const statRemaining  = document.getElementById('stat-remaining');
const pipelineFill   = document.getElementById('pipeline-fill');
const fetchBtn       = document.getElementById('fetch-btn');
const scanStartBtn   = document.getElementById('scan-start-btn');
const scanStopBtn    = document.getElementById('scan-stop-btn');
const pipelineNote   = document.getElementById('pipeline-note');

// DOM refs — manual scan + results
const urlsInput    = document.getElementById('urls-input');
const scanBtn      = document.getElementById('scan-btn');
const scanStatus   = document.getElementById('scan-status');
const resultsBody  = document.getElementById('results-body');
const emptyState   = document.getElementById('empty-state');
const resultsCount = document.getElementById('results-count');
const filterToggle = document.getElementById('filter-toggle');

// Pipeline state
let autoScanRunning = false;
let stopRequested   = false;
let filterHighValue = false;
let currentResults  = [];

// ── API helper ────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data;
  try { data = await res.json(); } catch { data = {}; }
  return { ok: res.ok, status: res.status, data };
}

// ── Auth ──────────────────────────────────────────────────────────────────
async function checkAuth() {
  try {
    const { data } = await api('GET', '/api/admin/check-auth');
    data.authed ? showDashboard() : showLogin();
  } catch { showLogin(); }
}

function showLogin() {
  loginView.hidden = false;
  dashView.hidden  = true;
  pwdInput.focus();
}

function showDashboard() {
  loginView.hidden = true;
  dashView.hidden  = false;
  loadQueueStats();
  loadResults();
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.hidden = true;
  const btn = loginForm.querySelector('button[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  try {
    const { ok, data } = await api('POST', '/api/admin/login', { password: pwdInput.value });
    if (ok) { pwdInput.value = ''; showDashboard(); }
    else { loginError.textContent = data.error || 'Incorrect password.'; loginError.hidden = false; pwdInput.select(); }
  } catch {
    loginError.textContent = 'Network error — server may be waking up. Try again in 10s.';
    loginError.hidden = false;
  } finally { btn.disabled = false; btn.textContent = 'Sign in'; }
});

logoutBtn.addEventListener('click', async () => {
  await api('POST', '/api/admin/logout');
  showLogin();
});

// ── Pipeline ──────────────────────────────────────────────────────────────
async function loadQueueStats() {
  try {
    const { data } = await api('GET', '/api/admin/queue-stats');
    updatePipelineStats(data);
  } catch {}
}

function updatePipelineStats(stats) {
  if (!stats) return;
  statTotal.textContent     = stats.total ?? '—';
  statDone.textContent      = stats.done  ?? '—';
  statRemaining.textContent = stats.pending ?? '—';
  const pct = stats.total > 0 ? Math.round((stats.done / stats.total) * 100) : 0;
  pipelineFill.style.width = `${pct}%`;
}

function setPipelineStatus(state) {
  pipelineStatus.className = 'pipeline-status';
  pipelineStatus.classList.add(`status--${state}`);
  const labels = { idle: 'Idle', running: 'Scanning…', done: 'Done' };
  pipelineStatus.textContent = labels[state] || state;
}

fetchBtn.addEventListener('click', async () => {
  fetchBtn.disabled    = true;
  fetchBtn.textContent = 'Fetching…';
  pipelineNote.textContent = 'Querying Common Crawl for Shopify stores…';
  try {
    const { ok, data } = await api('POST', '/api/admin/fetch-targets');
    if (ok) {
      pipelineNote.textContent = data.added > 0
        ? `✓ Added ${data.added} new stores to queue (${data.found} found total).`
        : `No new stores found (${data.found} found, all already in queue or scanned).`;
      updatePipelineStats(data.stats);
    } else {
      pipelineNote.textContent = 'Fetch failed — check server logs.';
    }
  } catch {
    pipelineNote.textContent = 'Network error during fetch.';
  } finally {
    fetchBtn.disabled    = false;
    fetchBtn.textContent = '🔍 Fetch Shopify stores';
  }
});

scanStartBtn.addEventListener('click', () => {
  if (autoScanRunning) return;
  startAutoScan();
});

scanStopBtn.addEventListener('click', () => {
  stopRequested = true;
  pipelineNote.textContent = 'Stopping after current batch…';
});

async function startAutoScan() {
  autoScanRunning    = true;
  stopRequested      = false;
  scanStartBtn.hidden = true;
  scanStopBtn.hidden  = false;
  setPipelineStatus('running');

  while (!stopRequested) {
    const { ok: bOk, data: bData } = await api('GET', '/api/admin/next-batch?n=25');
    if (!bOk) { pipelineNote.textContent = 'Failed to fetch next batch.'; break; }

    const domains = bData?.domains || [];
    if (domains.length === 0) {
      pipelineNote.textContent = '✓ Queue empty — all stores scanned!';
      setPipelineStatus('done');
      break;
    }

    pipelineNote.textContent = `Scanning ${domains.length} stores…`;
    const { ok, data } = await api('POST', '/api/admin/bulk-scan', { urls: domains });

    if (ok) {
      const good = (data.results || []).filter(r => r.ok).length;
      const bad  = domains.length - good;
      pipelineNote.textContent = `Batch done: ${good} scanned${bad ? `, ${bad} failed` : ''}.`;
    }

    await loadQueueStats();
    await loadResults();
  }

  autoScanRunning    = false;
  scanStartBtn.hidden = false;
  scanStopBtn.hidden  = true;
  if (stopRequested) { setPipelineStatus('idle'); pipelineNote.textContent = 'Stopped.'; }
}

// ── High-value filter ─────────────────────────────────────────────────────
filterToggle.addEventListener('click', () => {
  filterHighValue = !filterHighValue;
  filterToggle.textContent = filterHighValue ? '⚡ High-value only' : 'All stores';
  filterToggle.classList.toggle('btn-sm--pine', filterHighValue);
  renderResults(currentResults);
});

// ── Results ───────────────────────────────────────────────────────────────
async function loadResults() {
  const { ok, data } = await api('GET', '/api/admin/results');
  if (!ok) return;
  renderResults(data);
}

function scoreClass(score) {
  if (score >= 80) return 'score--good';
  if (score >= 60) return 'score--warn';
  return 'score--bad';
}

const STATUS_LABEL = { pending: 'Pending', sent: 'Sent', replied: 'Replied' };
const STATUS_NEXT  = { pending: 'sent', sent: 'replied', replied: 'pending' };
const SEV_CLASS    = { critical: 'sev--critical', warning: 'sev--warning', good: 'sev--good', info: 'sev--info' };

function renderResults(rows) {
  currentResults = rows;
  const toShow = filterHighValue
    ? rows.filter(r => (r.score ?? 100) < 65 && (r.trackers || []).length > 0 && !r.has_consent_layer)
    : rows;
  resultsCount.textContent = toShow.length
    ? `${toShow.length}${filterHighValue ? ' high-value' : ''} store${toShow.length !== 1 ? 's' : ''}`
    : '';
  emptyState.hidden = toShow.length > 0;
  if (!toShow.length) { resultsBody.innerHTML = ''; return; }
  const rows2 = toShow; // rebind for rest of function

  resultsBody.innerHTML = rows2.map((row) => {
    const trackerNames = Array.isArray(row.trackers)
      ? row.trackers.map((t) => t.name || t).filter(Boolean).join(', ') || '—'
      : '—';
    const sc = scoreClass(row.score ?? 0);
    const when = row.scanned_at
      ? new Date(row.scanned_at).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
      : '—';
    const nextSt = STATUS_NEXT[row.email_status] || 'sent';
    const hasFindings = Array.isArray(row.findings) && row.findings.length;

    const findingsHtml = hasFindings
      ? row.findings.map((f) => `
          <div class="finding-item">
            <span class="finding-sev ${SEV_CLASS[f.severity] || 'sev--info'}">${f.severity || 'info'}</span>
            <div>
              <div class="finding-text">${esc(f.title)}</div>
              ${f.detail ? `<div class="finding-detail">${esc(f.detail)}</div>` : ''}
            </div>
          </div>`).join('')
      : '<div style="font-size:0.82rem;color:var(--ink-faint)">No findings data (re-scan to populate).</div>';

    const cmpNames = Array.isArray(row.cmps) && row.cmps.length
      ? row.cmps.map((c) => c.name || c).join(', ')
      : null;

    return `
      <tr class="result-row" data-id="${row.id}">
        <td style="width:32px;padding-left:0.8rem;">
          <button class="btn-sm btn-toggle-findings" data-id="${row.id}" title="Show issues" style="padding:0.15rem 0.45rem;font-size:0.8rem;">▶</button>
        </td>
        <td class="td-domain">${esc(row.domain)}</td>
        <td class="td-score"><span class="score-badge ${sc}">${row.score ?? '?'}</span></td>
        <td class="td-trackers">${esc(trackerNames)}</td>
        <td class="td-date">${esc(when)}</td>
        <td class="td-status"><span class="status-badge status--${row.email_status}">${STATUS_LABEL[row.email_status] || row.email_status}</span></td>
        <td><div class="td-actions-inner">
          <button class="btn-sm btn-sm--pine btn-copy-email"
            data-domain="${esc(row.domain)}"
            data-score="${row.score ?? 0}"
            data-trackers="${esc(JSON.stringify(row.trackers || []))}">Copy email</button>
          <button class="btn-sm btn-toggle-status" data-id="${row.id}" data-next="${nextSt}">Mark ${STATUS_LABEL[nextSt]}</button>
          <button class="btn-sm btn-sm--danger btn-delete" data-id="${row.id}" data-domain="${esc(row.domain)}">Delete</button>
        </div></td>
      </tr>
      <tr class="findings-row" id="findings-${row.id}" hidden>
        <td colspan="7">
          <div class="findings-inner">
            <h4>Compliance issues${cmpNames ? ` · CMP detected: ${esc(cmpNames)}` : ''}</h4>
            ${findingsHtml}
          </div>
        </td>
      </tr>`;
  }).join('');
}

function esc(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildEmail(domain, score, trackers) {
  const names = trackers.map((t) => t.name || t).filter(Boolean);
  const trackerLine = names.length
    ? names.map((n) => `· ${n}`).join('\n')
    : '· tracking pixels firing before consent';

  return `Subject: Your store scored ${score}/100 on GDPR — here's what I found

Hi,

I ran a compliance scan on ${domain} and found something worth flagging:

${trackerLine}

These are loading before any consent is collected from visitors.
Under GDPR, that's a liability — fines can reach 2% of annual revenue.

I'm paperfox, I built the scanner that caught this.
If you want, I can send you a specific fix checklist for your setup — takes 5 minutes to read, might save you a serious headache.

Interested?

— paperfox
https://shopify-0c9l.onrender.com

(Reply STOP if you'd rather not hear from me.)`;
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return; }
  const ta = Object.assign(document.createElement('textarea'), { value: text });
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px';
  document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
}

// ── Table event delegation ────────────────────────────────────────────────
resultsBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;

  // Toggle findings row
  if (btn.classList.contains('btn-toggle-findings')) {
    const id = btn.dataset.id;
    const row = document.getElementById(`findings-${id}`);
    const expanded = !row.hidden;
    row.hidden = expanded;
    btn.textContent = expanded ? '▶' : '▼';
    return;
  }

  // Copy email
  if (btn.classList.contains('btn-copy-email')) {
    const trackers = JSON.parse(btn.dataset.trackers || '[]');
    const text = buildEmail(btn.dataset.domain, parseInt(btn.dataset.score, 10), trackers);
    try {
      await copyText(text);
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    } catch { btn.textContent = 'Error'; }
    return;
  }

  const id = parseInt(btn.dataset.id, 10);

  // Toggle status
  if (btn.classList.contains('btn-toggle-status')) {
    await api('POST', '/api/admin/update-status', { id, status: btn.dataset.next });
    loadResults();
    return;
  }

  // Delete
  if (btn.classList.contains('btn-delete')) {
    if (!confirm(`Delete scan for "${btn.dataset.domain}"?`)) return;
    await api('DELETE', `/api/admin/scan/${id}`);
    loadResults();
  }
});

// ── Batch scan ────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', async () => {
  const raw = urlsInput.value.trim();
  if (!raw) return;
  const urls = raw.split('\n').map((u) => u.trim()).filter(Boolean);
  if (!urls.length) return;
  if (urls.length > 25) { scanStatus.textContent = 'Max 25 URLs. Trim the list.'; return; }

  scanBtn.disabled = true;
  scanStatus.textContent = `Scanning ${urls.length} store${urls.length !== 1 ? 's' : ''}…`;

  const { ok, data } = await api('POST', '/api/admin/bulk-scan', { urls });
  if (ok) {
    const good = data.results.filter((r) => r.ok).length;
    const bad  = data.results.filter((r) => !r.ok).length;
    scanStatus.textContent = `Done — ${good} scanned${bad ? `, ${bad} failed` : ''}.`;
    urlsInput.value = '';
    loadResults();
  } else {
    scanStatus.textContent = data.error || 'Scan failed.';
  }
  scanBtn.disabled = false;
});

// ── Init ──────────────────────────────────────────────────────────────────
checkAuth();
