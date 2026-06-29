// server.js — Consentry Phase 0 validation site.
// Serves the static landing page and exposes POST /api/scan.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import session from 'express-session';
import { Resend } from 'resend';
import { scanStore, ScanError } from './scanner.js';
import { insertScan, listScans, setEmailStatus, removeScan } from './db.js';

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || '1qaz0726@gmail.com';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.disable('x-powered-by');
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

app.get('/api/admin/results', requireAdmin, (_req, res) => {
  res.json(listScans());
});

app.post('/api/admin/update-status', requireAdmin, (req, res) => {
  const { id, status } = req.body || {};
  if (!Number.isInteger(id) || !['pending', 'sent', 'replied'].includes(status)) {
    return res.status(400).json({ error: 'Invalid id or status.' });
  }
  setEmailStatus(id, status);
  res.json({ ok: true });
});

app.delete('/api/admin/scan/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id.' });
  removeScan(id);
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
        insertScan({
          domain,
          score:           result.score,
          level:           result.level,
          trackers:        result.trackers,
          cmps:            result.cmps,
          findings:        result.findings,
          hasConsentLayer: result.cmps.length > 0,
        });
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

// Domains that should never appear as "discovered" stores.
const EXCLUDED_DOMAINS = new Set([
  'shopify.com', 'myshopify.com', 'shopifyplus.com', 'shopify.dev',
  'apps.shopify.com', 'help.shopify.com', 'community.shopify.com',
  'youtube.com', 'reddit.com', 'twitter.com', 'x.com',
  'facebook.com', 'instagram.com', 'tiktok.com', 'pinterest.com',
  'medium.com', 'google.com', 'wikipedia.org', 'amazon.com',
  'hubspot.com', 'oberlo.com', 'ecwid.com', 'woocommerce.com',
]);

// Scrape DuckDuckGo HTML for "powered by shopify" <niche> results.
// Returns an array of {domain, niche} objects, or null on failure.
async function scrapeStoresFromDDG(niche) {
  const query = `"powered by shopify" ${niche}`;
  try {
    const res = await fetch('https://html.duckduckgo.com/html/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      body: new URLSearchParams({ q: query, b: '', kl: 'us-en' }).toString(),
      signal: AbortSignal.timeout(12000),
    });
    if (!res.ok) return null;
    const html = await res.text();

    const domains = new Set();

    // DDG HTML: <a class="result__url__domain" href="https://store.com">store.com</a>
    const domainLinks = [...html.matchAll(/class="result__url__domain"[^>]*href="(https?:\/\/[^"]+)"/gi)];
    for (const m of domainLinks) {
      try {
        const d = new URL(m[1]).hostname.replace(/^www\./, '').toLowerCase();
        if (d && d.includes('.') && !EXCLUDED_DOMAINS.has(d) && !d.includes('shopify')) domains.add(d);
      } catch {}
    }

    // Fallback: result__a href
    if (domains.size < 3) {
      const hrefs = [...html.matchAll(/class="result__a"[^>]+href="(https?:\/\/[^"]+)"/gi)];
      for (const m of hrefs) {
        try {
          const d = new URL(m[1]).hostname.replace(/^www\./, '').toLowerCase();
          if (d && d.includes('.') && !EXCLUDED_DOMAINS.has(d) && !d.includes('shopify')) domains.add(d);
        } catch {}
      }
    }

    const results = [...domains].slice(0, 20).map((domain) => ({ domain, niche }));
    return results.length > 0 ? results : null;
  } catch {
    return null;
  }
}

// Curated seed list — confirmed Shopify stores across niches.
// Used when GOOGLE_SEARCH_API_KEY is not set.
const SEED_STORES = [
  // Grooming / Personal care
  { domain: 'drsquatch.com',      niche: 'grooming' },
  { domain: 'beardbrand.com',     niche: 'grooming' },
  { domain: 'manscaped.com',      niche: 'grooming' },
  { domain: 'harrys.com',         niche: 'grooming' },
  // Fitness / Apparel
  { domain: 'gymshark.com',       niche: 'fitness' },
  { domain: 'figs.com',           niche: 'apparel' },
  { domain: 'cuts.com',           niche: 'apparel' },
  { domain: 'vuoriclothing.com',  niche: 'apparel' },
  { domain: 'chubbies.com',       niche: 'apparel' },
  // Footwear
  { domain: 'allbirds.com',       niche: 'footwear' },
  { domain: 'rothys.com',         niche: 'footwear' },
  // Beauty / Skincare
  { domain: 'glossier.com',       niche: 'beauty' },
  { domain: 'tatcha.com',         niche: 'beauty' },
  { domain: 'herbivore.com',      niche: 'beauty' },
  { domain: 'kiehlsofficial.com', niche: 'beauty' },
  // Supplements / Health
  { domain: 'liquid-iv.com',      niche: 'supplements' },
  { domain: 'ag1.com',            niche: 'supplements' },
  { domain: 'ritual.com',         niche: 'supplements' },
  // Home / Lifestyle
  { domain: 'brooklinen.com',     niche: 'home' },
  { domain: 'parachutehome.com',  niche: 'home' },
  { domain: 'ruggable.com',       niche: 'home' },
  { domain: 'graza.co',           niche: 'food' },
  // DTC / Tech
  { domain: 'away.com',           niche: 'travel' },
  { domain: 'mejuri.com',         niche: 'jewelry' },
  { domain: 'bombas.com',         niche: 'apparel' },
];

app.get('/api/admin/discover', requireAdmin, async (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q.trim().toLowerCase() : '';
  const googleKey = process.env.GOOGLE_SEARCH_API_KEY;
  const googleCx  = process.env.GOOGLE_SEARCH_CX;

  const scannedDomains = new Set(listScans().map((s) => s.domain));

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

  // --- Seed list fallback (shuffle for variety, filter already scanned) ---
  const base = q
    ? SEED_STORES.filter((s) => s.niche.includes(q) || s.domain.includes(q))
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

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => {
  console.log(`Consentry running at http://localhost:${PORT}`);
});
