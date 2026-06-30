// server.js — Consentry Phase 0 validation site.
// Serves the static landing page and exposes POST /api/scan.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import session from 'express-session';
import { Resend } from 'resend';
import { scanStore, ScanError } from './scanner.js';
import { insertScan, listScans, setEmailStatus, removeScan, getScanByDomain } from './db.js';
import { addToQueue, getNextBatch, markDone, getStats as getQueueStats, resetScanning } from './queue.js';

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || '1qaz0726@gmail.com';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.disable('x-powered-by');
resetScanning().catch(console.error); // restore mid-flight queue items to pending on restart
// Behind a known proxy/CDN set TRUST_PROXY so req.ip reflects the real client.
// Accept a hop count ("1"), a boolean ("true"/"false"), or a CIDR/preset list
// ("loopback", "10.0.0.0/8"). Coerce numeric/boolean strings explicitly —
// Express treats a bare string as a subnet list, not a hop count.
if (process.env.TRUST_PROXY) {
  const raw = process.env.TRUST_PROXY.trim();
  let trust;
  if (/^\d+$/.test(raw)) trust = Number(raw);
  else if (raw === 'true') trust = true;
  else if (raw === 'false') trust = false;
  else trust = raw;
  app.set('trust proxy', trust);
}
app.use(express.json({ limit: '8kb' }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'consentry-change-me-in-prod',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: !!process.env.TRUST_PROXY,
      maxAge: 8 * 60 * 60 * 1000,
    },
  }),
);

// Baseline security headers.
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
    ].join('; '),
  );
  next();
});

// --- Lightweight in-memory rate limit -------------------------------------
// Keeps a single visitor from hammering the scan endpoint. Good enough for a
// validation site; swap for a shared store if this ever scales out.
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 12;
const hits = new Map();

function rateLimit(req, res, next) {
  // Use req.ip only. X-Forwarded-For is attacker-controlled unless a trusted
  // proxy is configured; in production set TRUST_PROXY and Express will derive
  // req.ip from XFF safely.
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || now - entry.start > WINDOW_MS) {
    hits.set(ip, { start: now, count: 1 });
    return next();
  }
  entry.count += 1;
  if (entry.count > MAX_PER_WINDOW) {
    return res.status(429).json({ error: 'Too many scans. Give it a minute and try again.' });
  }
  next();
}

// Evict stale rate-limit buckets so the map cannot grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of hits) {
    if (now - entry.start > WINDOW_MS) hits.delete(ip);
  }
}, WINDOW_MS).unref();

// Global concurrency cap. Each scan makes an outbound fetch, so without a
// ceiling a flood of requests (even across spoofed IPs) could turn this into an
// outbound-scanning proxy / exhaust sockets. Excess requests are shed with 503.
const MAX_CONCURRENT_SCANS = 6;
let activeScans = 0;

app.post('/api/scan', rateLimit, async (req, res) => {
  const { url } = req.body || {};
  if (typeof url !== 'string') {
    return res.status(400).json({ error: 'Please enter a store URL.' });
  }
  if (activeScans >= MAX_CONCURRENT_SCANS) {
    return res.status(503).json({ error: 'We are scanning a lot of stores right now — try again in a moment.' });
  }
  activeScans += 1;
  try {
    const result = await scanStore(url);
    res.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return res.status(err.status).json({ error: err.message });
    }
    console.error('Unexpected scan error:', err);
    res.status(500).json({ error: 'Something went wrong on our side. Please try again.' });
  } finally {
    activeScans -= 1;
  }
});

app.post('/api/waitlist', async (req, res) => {
  const { email, url, score, findings, trackers } = req.body || {};
  if (typeof email !== 'string' || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Invalid email.' });
  }
  const safeEmail = email.trim().slice(0, 200);
  const safeUrl = typeof url === 'string' ? url.trim().slice(0, 500) : 'unknown';
  const safeScore = Number.isFinite(Number(score)) ? Math.round(Number(score)) : '?';

  const trackerNames = Array.isArray(trackers)
    ? trackers.map((t) => (typeof t === 'object' ? t.name : String(t))).filter(Boolean).join(', ')
    : '';
  const findingLines = Array.isArray(findings)
    ? findings
        .filter((f) => f.severity === 'critical' || f.severity === 'warning')
        .map((f) => `  [${f.severity.toUpperCase()}] ${f.title}`)
        .join('\n')
    : '';

  const body =
    `New waitlist signup:\n\n` +
    `Email:    ${safeEmail}\n` +
    `Scanned:  ${safeUrl}\n` +
    `Score:    ${safeScore}/100\n` +
    (trackerNames ? `Trackers: ${trackerNames}\n` : '') +
    (findingLines ? `\nIssues found:\n${findingLines}\n` : '');

  if (resend) {
    try {
      await resend.emails.send({
        from: 'Consentry <onboarding@resend.dev>',
        to: NOTIFY_EMAIL,
        subject: `New lead — ${safeEmail} (score ${safeScore}/100)`,
        text: body,
      });
    } catch (err) {
      console.error('Resend error:', err.message);
    }
  } else {
    console.log(`[waitlist]\n${body}`);
  }
  res.json({ ok: true });
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------------------
// Admin panel
// ---------------------------------------------------------------------------

function requireAdmin(req, res, next) {
  if (req.session?.adminAuthed) return next();
  return res.status(401).json({ error: 'Unauthorized.' });
}

const loginAttempts = new Map();
setInterval(() => loginAttempts.clear(), 60_000).unref();

app.post('/api/admin/login', (req, res) => {
  const adminPwd = process.env.ADMIN_PASSWORD;
  if (!adminPwd) return res.status(503).json({ error: 'Admin is not configured on this server.' });

  const ip = req.ip || 'unknown';
  const attempts = (loginAttempts.get(ip) || 0) + 1;
  loginAttempts.set(ip, attempts);
  if (attempts > 10) return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });

  const { password } = req.body || {};
  if (typeof password !== 'string' || password !== adminPwd) {
    return res.status(401).json({ error: 'Incorrect password.' });
  }
  req.session.adminAuthed = true;
  loginAttempts.set(ip, 0);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

app.get('/api/admin/check-auth', (req, res) => {
  res.json({ authed: !!req.session?.adminAuthed });
});

app.get('/api/admin/results', requireAdmin, async (_req, res) => {
  try {
    res.json(await listScans());
  } catch (err) {
    console.error('listScans error:', err);
    res.status(500).json({ error: 'Failed to load results.' });
  }
});

app.post('/api/admin/update-status', requireAdmin, async (req, res) => {
  const { id, status } = req.body || {};
  if (!Number.isInteger(id) || !['pending', 'sent', 'replied'].includes(status)) {
    return res.status(400).json({ error: 'Invalid id or status.' });
  }
  await setEmailStatus(id, status);
  res.json({ ok: true });
});

app.delete('/api/admin/scan/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id.' });
  await removeScan(id);
  res.json({ ok: true });
});

const BULK_CONCURRENCY = 4;
const BULK_MAX = 25;

async function runBulkScans(urls) {
  const results = [];
  for (let i = 0; i < urls.length; i += BULK_CONCURRENCY) {
    const chunk = urls.slice(i, i + BULK_CONCURRENCY);
    const settled = await Promise.allSettled(
      chunk.map(async (rawUrl) => {
        const result = await scanStore(rawUrl);
        const domain = new URL(result.finalUrl).hostname;
        await insertScan({
          domain,
          score:           result.score,
          level:           result.level,
          trackers:        result.trackers,
          cmps:            result.cmps,
          findings:        result.findings,
          hasConsentLayer: result.cmps.length > 0,
        });
        await markDone(rawUrl.replace(/^https?:\/\//i, '').split('/')[0]);
        return { domain, score: result.score, ok: true };
      }),
    );
    for (let j = 0; j < settled.length; j++) {
      const item = settled[j];
      if (item.status === 'fulfilled') {
        results.push(item.value);
      } else {
        const raw = chunk[j];
        const domain = raw.replace(/^https?:\/\//i, '').split('/')[0];
        const msg = item.reason instanceof ScanError ? item.reason.message : 'Scan failed.';
        await markDone(domain); // mark failed scans done so queue doesn't retry indefinitely
        results.push({ domain, ok: false, error: msg });
      }
    }
  }
  return results;
}

app.post('/api/admin/bulk-scan', requireAdmin, async (req, res) => {
  const { urls } = req.body || {};
  if (!Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: 'Provide a non-empty array of URLs.' });
  }
  if (urls.length > BULK_MAX) {
    return res.status(400).json({ error: `Max ${BULK_MAX} URLs per batch.` });
  }
  const cleanUrls = urls.filter((u) => typeof u === 'string' && u.trim()).map((u) => u.trim());
  try {
    const results = await runBulkScans(cleanUrls);
    res.json({ results });
  } catch (err) {
    console.error('Bulk scan error:', err);
    res.status(500).json({ error: 'Bulk scan failed.' });
  }
});

// Subdomains that belong to Shopify infrastructure, not real stores.
const CC_SKIP = new Set([
  'cdn', 'cdn2', 'cdn3', 'static', 'checkout', 'www', 'shop',
  'assets', 'maps', 'proxy', 'help', 'community', 'partners',
]);

// Fetch real Shopify store domains from Common Crawl CDX API.
// This is a free public API designed for programmatic access — not blocked on cloud IPs.
// Queries *.myshopify.com across the 3 most recent crawl indexes and returns unique store domains.
async function fetchStoreTargets() {
  const allDomains = new Set();

  // Get the most recent crawl indexes (fallback to known ones if API fails)
  let indexes = ['CC-MAIN-2024-33', 'CC-MAIN-2024-26', 'CC-MAIN-2024-18'];
  try {
    const infoRes = await fetch('https://index.commoncrawl.org/collinfo.json', {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/json' },
    });
    if (infoRes.ok) {
      const info = await infoRes.json();
      indexes = info.slice(0, 3).map((c) => c.id);
    }
  } catch {}

  // Query each index for *.myshopify.com — response is newline-delimited JSON
  for (const idx of indexes) {
    if (allDomains.size >= 400) break;
    try {
      const apiUrl = `https://index.commoncrawl.org/${idx}-index?url=*.myshopify.com&output=json&fl=url&limit=500`;
      const res = await fetch(apiUrl, {
        signal: AbortSignal.timeout(25000),
        headers: { Accept: 'application/json, text/plain' },
      });
      if (!res.ok) continue;
      const text = await res.text();
      for (const line of text.trim().split('\n')) {
        if (!line) continue;
        try {
          const { url: pageUrl } = JSON.parse(line);
          const m = String(pageUrl).match(/^https?:\/\/([a-z0-9][a-z0-9-]{0,59})\.myshopify\.com/i);
          if (m && !CC_SKIP.has(m[1].toLowerCase())) {
            allDomains.add(`${m[1].toLowerCase()}.myshopify.com`);
          }
        } catch {}
      }
    } catch {}
  }

  return [...allDomains];
}

const EXCLUDED_DOMAINS = new Set([
  'shopify.com', 'myshopify.com', 'shopifyplus.com', 'shopify.dev',
  'apps.shopify.com', 'help.shopify.com', 'community.shopify.com',
  'youtube.com', 'reddit.com', 'twitter.com', 'x.com',
  'facebook.com', 'instagram.com', 'tiktok.com', 'pinterest.com',
  'medium.com', 'google.com', 'wikipedia.org', 'amazon.com',
  'hubspot.com', 'oberlo.com', 'ecwid.com', 'woocommerce.com',
  'shopifyeducation.com', 'linktr.ee', 'linkinbio.com',
]);

function isValidStoreDomain(d) {
  return (
    d && d.includes('.') &&
    !EXCLUDED_DOMAINS.has(d) &&
    !d.includes('shopify') &&
    d.split('.').length <= 3 &&
    !/^(blog|docs|support|help|www2|cdn|api|mail|news|shop)\./i.test(d)
  );
}

// Try DDG Lite first (lighter bot detection), then DDG HTML POST as fallback.
// Both search for "powered by shopify <niche>" and extract result domains.
async function scrapeStoresFromDDG(niche) {
  const query = `"powered by shopify" ${niche}`;

  // ── DDG Lite (GET) ────────────────────────────────────────────
  try {
    const res = await fetch(
      `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}&kl=us-en`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html',
          'Accept-Language': 'en-US,en;q=0.9',
        },
        signal: AbortSignal.timeout(10000),
      }
    );
    if (res.ok) {
      const html = await res.text();
      const domains = new Set();
      // DDG Lite encodes result URLs as uddg= in redirect hrefs
      for (const m of html.matchAll(/uddg=([^&"'\s]+)/gi)) {
        try {
          const d = new URL(decodeURIComponent(m[1])).hostname.replace(/^www\./, '').toLowerCase();
          if (isValidStoreDomain(d)) domains.add(d);
        } catch {}
      }
      if (domains.size > 0) return [...domains].slice(0, 20).map((domain) => ({ domain, niche }));
    }
  } catch {}

  // ── DDG HTML (POST fallback) ──────────────────────────────────
  try {
    const res = await fetch('https://html.duckduckgo.com/html/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      body: new URLSearchParams({ q: query, b: '', kl: 'us-en' }).toString(),
      signal: AbortSignal.timeout(10000),
    });
    if (res.ok) {
      const html = await res.text();
      const domains = new Set();
      for (const m of html.matchAll(/uddg=([^&"'\s]+)/gi)) {
        try {
          const d = new URL(decodeURIComponent(m[1])).hostname.replace(/^www\./, '').toLowerCase();
          if (isValidStoreDomain(d)) domains.add(d);
        } catch {}
      }
      for (const m of html.matchAll(/class="result__url__domain"[^>]*href="(https?:\/\/[^"]+)"/gi)) {
        try {
          const d = new URL(m[1]).hostname.replace(/^www\./, '').toLowerCase();
          if (isValidStoreDomain(d)) domains.add(d);
        } catch {}
      }
      if (domains.size > 0) return [...domains].slice(0, 20).map((domain) => ({ domain, niche }));
    }
  } catch {}

  return null;
}

// Curated seed stores — fallback when DDG / Google Search unavailable.
// Niches are single keywords; keyword matching in the discover endpoint
// splits the query so "pet supplies" matches stores with niche "pet".
const SEED_STORES = [
  // Grooming
  { domain: 'drsquatch.com',       niche: 'grooming' },
  { domain: 'beardbrand.com',      niche: 'grooming' },
  { domain: 'manscaped.com',       niche: 'grooming' },
  { domain: 'harrys.com',          niche: 'grooming' },
  // Pet
  { domain: 'ruffwear.com',        niche: 'pet' },
  { domain: 'barkshop.com',        niche: 'pet' },
  { domain: 'wildone.com',         niche: 'pet' },
  { domain: 'yummers.com',         niche: 'pet' },
  { domain: 'pupford.com',         niche: 'pet' },
  // Supplements / Health
  { domain: 'liquid-iv.com',       niche: 'supplements' },
  { domain: 'ag1.com',             niche: 'supplements' },
  { domain: 'ritual.com',          niche: 'supplements' },
  { domain: 'momentous.com',       niche: 'supplements' },
  { domain: 'organifi.com',        niche: 'supplements' },
  { domain: 'promixnutrition.com', niche: 'supplements' },
  // Beauty / Skincare
  { domain: 'glossier.com',        niche: 'beauty' },
  { domain: 'tatcha.com',          niche: 'beauty' },
  { domain: 'herbivore.com',       niche: 'beauty' },
  { domain: 'necessaire.com',      niche: 'beauty' },
  { domain: 'cocokind.com',        niche: 'beauty' },
  { domain: 'topicals.co',         niche: 'beauty' },
  // Fitness / Apparel / Fashion
  { domain: 'gymshark.com',        niche: 'fitness' },
  { domain: 'figs.com',            niche: 'apparel' },
  { domain: 'cuts.com',            niche: 'apparel' },
  { domain: 'vuoriclothing.com',   niche: 'apparel' },
  { domain: 'chubbies.com',        niche: 'apparel' },
  { domain: 'summersalt.com',      niche: 'apparel' },
  { domain: 'bombas.com',          niche: 'apparel' },
  // Footwear
  { domain: 'allbirds.com',        niche: 'footwear' },
  { domain: 'rothys.com',          niche: 'footwear' },
  // Home / Lifestyle
  { domain: 'brooklinen.com',      niche: 'home' },
  { domain: 'parachutehome.com',   niche: 'home' },
  { domain: 'ruggable.com',        niche: 'home' },
  { domain: 'snowe.com',           niche: 'home' },
  { domain: 'ugmonk.com',          niche: 'home' },
  // Food / Beverage
  { domain: 'graza.co',            niche: 'food' },
  { domain: 'omsom.com',           niche: 'food' },
  { domain: 'brightland.co',       niche: 'food' },
  { domain: 'diasporaco.com',      niche: 'food' },
  // Jewelry / Accessories
  { domain: 'mejuri.com',          niche: 'jewelry' },
  { domain: 'gorjana.com',         niche: 'jewelry' },
  { domain: 'aurate.com',          niche: 'jewelry' },
  // Travel / Bags
  { domain: 'away.com',            niche: 'travel' },
  { domain: 'wandrd.com',          niche: 'travel' },
];

// Queue stats
app.get('/api/admin/queue-stats', requireAdmin, async (_req, res) => {
  res.json(await getQueueStats());
});

// Next batch of unscanned domains
app.get('/api/admin/next-batch', requireAdmin, async (req, res) => {
  const n = Math.min(parseInt(req.query.n) || 25, 25);
  const domains = await getNextBatch(n);
  res.json({ domains, stats: await getQueueStats() });
});

// Fetch Shopify store targets from Common Crawl CDX API and add to queue
app.post('/api/admin/fetch-targets', requireAdmin, async (req, res) => {
  const found = await fetchStoreTargets();
  const scannedSet = new Set((await listScans()).map((s) => s.domain));
  const fresh = found.filter((d) => !scannedSet.has(d));
  const added = await addToQueue(fresh);
  res.json({ added, found: found.length, stats: await getQueueStats() });
});

// Manually add domains to queue
app.post('/api/admin/add-to-queue', requireAdmin, async (req, res) => {
  const { domains } = req.body || {};
  if (!Array.isArray(domains) || !domains.length) {
    return res.status(400).json({ error: 'Provide a non-empty domains array.' });
  }
  const scannedSet = new Set((await listScans()).map((s) => s.domain));
  const fresh = domains.filter((d) => typeof d === 'string' && !scannedSet.has(d.trim()));
  const added = await addToQueue(fresh);
  res.json({ added, stats: await getQueueStats() });
});

app.get('/api/admin/discover', requireAdmin, async (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
  const googleKey = process.env.GOOGLE_SEARCH_API_KEY;
  const googleCx  = process.env.GOOGLE_SEARCH_CX;

  const scannedDomains = new Set((await listScans()).map((s) => s.domain));

  // --- Google Custom Search (if configured) ---
  if (googleKey && googleCx) {
    try {
      const query = encodeURIComponent(`"cdn.shopify.com" ${q || 'store'}`);
      const apiUrl = `https://www.googleapis.com/customsearch/v1?key=${googleKey}&cx=${googleCx}&q=${query}&num=10`;
      const gRes = await fetch(apiUrl, {
        signal: AbortSignal.timeout(8000),
        headers: { Accept: 'application/json' },
      });
      if (gRes.ok) {
        const data = await gRes.json();
        const domains = (data.items || [])
          .map((item) => { try { return new URL(item.link).hostname.replace(/^www\./, ''); } catch { return null; } })
          .filter(Boolean)
          .filter((d, i, a) => a.indexOf(d) === i)
          .filter((d) => !scannedDomains.has(d));
        return res.json({ domains, source: 'google', hasApiKey: true, scannedCount: scannedDomains.size });
      }
    } catch { /* fall through */ }
  }

  // --- DuckDuckGo live search (when a keyword is given) ---
  if (q) {
    const ddgResults = await scrapeStoresFromDDG(q);
    if (ddgResults && ddgResults.length > 0) {
      const fresh = ddgResults.filter((s) => !scannedDomains.has(s.domain));
      return res.json({ domains: fresh, source: 'ddg', hasApiKey: false, scannedCount: scannedDomains.size });
    }
  }

  // --- Seed list fallback (keyword split, shuffle, filter already scanned) ---
  // Split multi-word queries so "pet supplies" matches niche "pet".
  const keywords = q ? q.split(/\s+/).filter((kw) => kw.length > 2) : [];
  const base = keywords.length
    ? SEED_STORES.filter((s) => keywords.some((kw) => s.niche.includes(kw) || s.domain.includes(kw)))
    : SEED_STORES;
  const unscanned = base.filter((s) => !scannedDomains.has(s.domain));
  const shuffled  = [...unscanned].sort(() => Math.random() - 0.5).slice(0, 25);
  res.json({
    domains:      shuffled.map((s) => ({ domain: s.domain, niche: s.niche })),
    source:       'seed',
    hasApiKey:    false,
    scannedCount: scannedDomains.size,
  });
});

// Public report page — served to store owners via the link in the cold email.
app.get('/report/:domain', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

// Public report data API — no auth, intentionally public (it's about publicly visible store behaviour).
app.get('/api/report/:domain', async (req, res) => {
  const domain = req.params.domain.toLowerCase().replace(/^www\./, '');
  if (!domain || !domain.includes('.')) {
    return res.status(400).json({ error: 'Invalid domain.' });
  }
  try {
    const scan = await getScanByDomain(domain);
    if (!scan) return res.status(404).json({ error: 'Report not found.' });
    res.json({ ...scan, contactEmail: process.env.NOTIFY_EMAIL || '1qaz0726@gmail.com' });
  } catch (err) {
    console.error('Report lookup error:', err);
    res.status(500).json({ error: 'Failed to load report.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => {
  console.log(`Consentry running at http://localhost:${PORT}`);
});
