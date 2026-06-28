// admin.js — Consentry admin dashboard client.

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
  const { data } = await api('GET', '/api/admin/check-auth');
  data.authed ? showDashboard() : showLogin();
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
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  loginError.hidden = true;
  const { ok, data } = await api('POST', '/api/admin/login', { password: pwdInput.value });
  if (ok) {
    pwdInput.value = '';
    showDashboard();
  } else {
    loginError.textContent = data.error || 'Incorrect password.';
    loginError.hidden = false;
    pwdInput.select();
  }
});

logoutBtn.addEventListener('click', async () => {
  await api('POST', '/api/admin/logout');
  showLogin();
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

function renderResults(rows) {
  const count = rows.length;
  resultsCount.textContent = count ? `${count} store${count !== 1 ? 's' : ''}` : '';
  emptyState.hidden = count > 0;

  if (!count) { resultsBody.innerHTML = ''; return; }

  resultsBody.innerHTML = rows.map((row) => {
    const trackerNames = Array.isArray(row.trackers)
      ? row.trackers.map((t) => t.name || t).filter(Boolean).join(', ') || '—'
      : '—';
    const sc = scoreClass(row.score ?? 0);
    const when = row.scanned_at
      ? new Date(row.scanned_at).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
      : '—';
    const nextSt = STATUS_NEXT[row.email_status] || 'sent';

    return `<tr data-id="${row.id}">
      <td class="td-domain">${esc(row.domain)}</td>
      <td class="td-score"><span class="score-badge ${sc}">${row.score ?? '?'}</span></td>
      <td class="td-trackers">${esc(trackerNames)}</td>
      <td class="td-date">${esc(when)}</td>
      <td class="td-status"><span class="status-badge status--${row.email_status}">${STATUS_LABEL[row.email_status] || row.email_status}</span></td>
      <td class="td-actions">
        <button class="btn-sm btn-sm--pine btn-copy-email"
          data-domain="${esc(row.domain)}"
          data-score="${row.score ?? 0}"
          data-trackers="${esc(JSON.stringify(row.trackers || []))}">Copy email</button>
        <button class="btn-sm btn-toggle-status" data-id="${row.id}" data-next="${nextSt}">Mark ${STATUS_LABEL[nextSt]}</button>
        <button class="btn-sm btn-sm--danger btn-delete" data-id="${row.id}" data-domain="${esc(row.domain)}">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  ta.remove();
}

// ── Table event delegation ────────────────────────────────────────────────
resultsBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;

  if (btn.classList.contains('btn-copy-email')) {
    const trackers = JSON.parse(btn.dataset.trackers || '[]');
    const text = buildEmail(btn.dataset.domain, parseInt(btn.dataset.score, 10), trackers);
    try {
      await copyText(text);
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 2000);
    } catch {
      btn.textContent = 'Error';
    }
    return;
  }

  const id = parseInt(btn.dataset.id, 10);

  if (btn.classList.contains('btn-toggle-status')) {
    await api('POST', '/api/admin/update-status', { id, status: btn.dataset.next });
    loadResults();
    return;
  }

  if (btn.classList.contains('btn-delete')) {
    if (!confirm(`Delete scan for "${btn.dataset.domain}"?`)) return;
    await api('DELETE', `/api/admin/scan/${id}`);
    loadResults();
  }
});

// ── Bulk scan ─────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', async () => {
  const raw = urlsInput.value.trim();
  if (!raw) return;

  const urls = raw.split('\n').map((u) => u.trim()).filter(Boolean);
  if (!urls.length) return;
  if (urls.length > 25) {
    scanStatus.textContent = 'Max 25 URLs at once. Trim the list.';
    return;
  }

  scanBtn.disabled = true;
  scanStatus.textContent = `Scanning ${urls.length} store${urls.length !== 1 ? 's' : ''}… (~${Math.ceil(urls.length * 5 / 4)}s)`;

  const { ok, data } = await api('POST', '/api/admin/bulk-scan', { urls });

  if (ok) {
    const good = data.results.filter((r) => r.ok).length;
    const bad  = data.results.filter((r) => !r.ok).length;
    scanStatus.textContent = `Done — ${good} scanned${bad ? `, ${bad} failed` : ''}.`;
    urlsInput.value = '';
    loadResults();
  } else {
    scanStatus.textContent = data.error || 'Scan failed. Try again.';
  }

  scanBtn.disabled = false;
});

// ── Init ──────────────────────────────────────────────────────────────────
checkAuth();
