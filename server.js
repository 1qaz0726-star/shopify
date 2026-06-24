// server.js — Consentry Phase 0 validation site.
// Serves the static landing page and exposes POST /api/scan.

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanStore, ScanError } from './scanner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.disable('x-powered-by');
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
  const ip = (req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown').trim();
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

app.post('/api/scan', rateLimit, async (req, res) => {
  const { url } = req.body || {};
  if (typeof url !== 'string') {
    return res.status(400).json({ error: 'Please enter a store URL.' });
  }
  try {
    const result = await scanStore(url);
    res.json(result);
  } catch (err) {
    if (err instanceof ScanError) {
      return res.status(err.status).json({ error: err.message });
    }
    console.error('Unexpected scan error:', err);
    res.status(500).json({ error: 'Something went wrong on our side. Please try again.' });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

app.listen(PORT, () => {
  console.log(`Consentry running at http://localhost:${PORT}`);
});
