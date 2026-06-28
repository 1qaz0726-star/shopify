// admin.js — Consentry admin dashboard

const SCANNER_URL = 'https://shopify-0c9l.onrender.com/';

// DOM refs
const loginView    = document.getElementById('login-view');
const dashView     = document.getElementById('dashboard-view');
const loginForm    = document.getElementById('login-form');
const loginError   = document.getElementById('login-error');
const pwdInput     = document.getElementById('pwd-input');
const logoutBtn    = document.getElementById('logout-btn');
const urlsInput    = document.getElementById('urls-input');
const scanBtn      = document.getElementById('scan-btn');
const scanStatus   = document.getElementById('scan-status');
const resultsBody  = document.getElementById('results-body');
const emptyState   = document.getElementById('empty-state');
const resultsCount = document.getElementById('results-count');
const discoverInput  = document.getElementById('discover-input');
const discoverBtn    = document.getElementById('discover-btn');
const discoverList   = document.getElementById('discover-list');
const discoverNote   = document.getElementById('discover-note');
const discoverSource = document.getElementById('discover-source');

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
  loadResults();
  loadDiscover('');
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

// ── Discover stores ───────────────────────────────────────────────────────
async function loadDiscover(q) {
  discoverBtn.disabled = true;
  discoverList.innerHTML = '<p style="font-size:0.82rem;color:var(--ink-faint);font-family:var(--mono);margin:0.75rem 0 0">Loading…</p>';
  discoverNote.hidden = true;

  try {
    const { data } = await api('GET', `/api/admin/discover?q=${encodeURIComponent(q)}`);
    discoverSource.textContent = data.source === 'google' ? 'via Google Search' : 'curated list';

    const items = data.domains || [];
    if (!items.length) {
      discoverList.innerHTML = '<p style="font-size:0.82rem;color:var(--ink-faint);font-family:var(--mono);margin:0.75rem 0 0">No results found.</p>';
    } else {
      discoverList.innerHTML = items.map((item) => {
        const domain = typeof item === 'string' ? item : item.domain;
        const niche  = typeof item === 'object' && item.niche ? item.niche : '';
        return `<div class="discover-item">
          <div>
            ${niche ? `<span class="discover-item__niche">${esc(niche)}</span>` : ''}
            <span class="discover-item__domain">${esc(domain)}</span>
          </div>
          <button class="btn-sm btn-sm--pine btn-add-to-scan" data-domain="${esc(domain)}">+ Add</button>
        </div>`;
      }).join('');
    }

    if (!data.hasApiKey) {
      discoverNote.innerHTML = 'Showing curated list. <a href="https://programmablesearch.google.com/" target="_blank" rel="noopener">Set up Google Search API</a> for live niche search → add <code>GOOGLE_SEARCH_API_KEY</code> + <code>GOOGLE_SEARCH_CX</code> to Render env vars.';
      discoverNote.hidden = false;
    }
  } catch {
    discoverList.innerHTML = '<p style="font-size:0.82rem;color:var(--bad);font-family:var(--mono);margin:0.75rem 0 0">Failed to load.</p>';
  } finally { discoverBtn.disabled = false; }
}

discoverBtn.addEventListener('click', () => loadDiscover(discoverInput.value.trim()));
discoverInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') loadDiscover(discoverInput.value.trim()); });

discoverList.addEventListener('click', (e) => {
  const btn = e.target.closest('.btn-add-to-scan');
  if (!btn) return;
  const domain = btn.dataset.domain;
  const current = urlsInput.value.trim();
  if (!current.split('\n').map(l => l.trim()).includes(domain)) {
    urlsInput.value = current ? current + '\n' + domain : domain;
  }
  btn.textContent = '✓ Added';
  btn.disabled = true;
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
  resultsCount.textContent = rows.length ? `${rows.length} store${rows.length !== 1 ? 's' : ''}` : '';
  emptyState.hidden = rows.length > 0;
  if (!rows.length) { resultsBody.innerHTML = ''; return; }

  resultsBody.innerHTML = rows.map((row) => {
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
  const list = trackers.map((t) => t.name || t).filter(Boolean).join(', ');
  return [
    `Subject: Quick compliance check on ${domain}`,
    '',
    'Hi,',
    '',
    `I built a free GDPR scanner for Shopify stores and tested it on ${domain} — score came back ${score}/100.`,
    '',
    list ? `Found: ${list} loading before consent.` : '',
    '',
    `Free report: ${SCANNER_URL}`,
    '',
    '— paperfox',
  ].filter((l, i, a) => !(l === '' && a[i - 1] === '')).join('\n').trim();
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
