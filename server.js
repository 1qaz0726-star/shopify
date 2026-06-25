// server.js — Consentry Phase 0 validation site.
// Serves the static landing page and exposes POST /api/scan.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Resend } from 'resend';
import { scanStore, ScanError } from './scanner.js';

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

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => {
  console.log(`Consentry running at http://localhost:${PORT}`);
});
