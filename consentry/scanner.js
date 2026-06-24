// scanner.js — compliance scan engine for Shopify storefronts.
// Fetches a storefront's HTML and statically detects (a) tracking technologies
// that typically fire on page load and (b) whether a consent-management layer
// is present. The verdict flags the common GDPR failure mode: trackers firing
// before the visitor has consented.

import * as cheerio from 'cheerio';
import dns from 'node:dns/promises';
import net from 'node:net';

const FETCH_TIMEOUT_MS = 12000;
const MAX_BYTES = 2_500_000; // 2.5 MB cap on the downloaded document
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/124.0 Safari/537.36 Consentry/0.1 (+compliance-scan)';

// --- Tracking technology signatures ---------------------------------------
// Each signature is matched (case-insensitively) against the raw HTML, the
// collected <script src> values and inline script bodies.
const TRACKERS = [
  { key: 'ga4', name: 'Google Analytics (GA4)', patterns: [/googletagmanager\.com\/gtag\/js/i, /www\.google-analytics\.com/i, /gtag\(\s*['"]config['"]/i] },
  { key: 'gtm', name: 'Google Tag Manager', patterns: [/googletagmanager\.com\/gtm\.js/i, /\bGTM-[A-Z0-9]{4,}\b/] },
  { key: 'meta', name: 'Meta (Facebook) Pixel', patterns: [/connect\.facebook\.net\/[^"']*\/fbevents\.js/i, /\bfbq\(\s*['"]init['"]/i] },
  { key: 'tiktok', name: 'TikTok Pixel', patterns: [/analytics\.tiktok\.com/i, /\bttq\.(load|track|page)\b/i] },
  { key: 'pinterest', name: 'Pinterest Tag', patterns: [/ct\.pinterest\.com/i, /\bpintrk\(/i] },
  { key: 'snapchat', name: 'Snapchat Pixel', patterns: [/sc-static\.net\/scevent/i, /\bsnaptr\(/i] },
  { key: 'hotjar', name: 'Hotjar', patterns: [/static\.hotjar\.com/i, /\bhj\(/] },
  { key: 'clarity', name: 'Microsoft Clarity', patterns: [/\.clarity\.ms\//i, /\bclarity\(\s*['"]/i] },
  { key: 'twitter', name: 'X (Twitter) Pixel', patterns: [/static\.ads-twitter\.com/i, /\btwq\(/i] },
  { key: 'linkedin', name: 'LinkedIn Insight Tag', patterns: [/snap\.licdn\.com/i, /_linkedin_partner_id/i] },
  { key: 'klaviyo', name: 'Klaviyo Onsite', patterns: [/static\.klaviyo\.com\/onsite/i, /klaviyo\.js/i] },
];

// --- Consent-management platform (CMP) signatures -------------------------
const CMPS = [
  { key: 'onetrust', name: 'OneTrust', patterns: [/cdn\.cookielaw\.org/i, /otSDKStub/i, /optanon/i] },
  { key: 'cookiebot', name: 'Cookiebot', patterns: [/consent\.cookiebot\.com/i, /\bCookiebot\b/] },
  { key: 'cookieyes', name: 'CookieYes', patterns: [/cdn-cookieyes\.com/i, /cookieyes/i] },
  { key: 'termly', name: 'Termly', patterns: [/app\.termly\.io/i, /termly/i] },
  { key: 'iubenda', name: 'iubenda', patterns: [/cdn\.iubenda\.com/i, /iubenda/i] },
  { key: 'osano', name: 'Osano', patterns: [/cmp\.osano\.com/i, /\bosano\b/i] },
  { key: 'complianz', name: 'Complianz', patterns: [/complianz/i] },
  { key: 'pandectes', name: 'Pandectes GDPR', patterns: [/pandectes/i] },
  {
    key: 'shopify-native',
    name: 'Shopify Customer Privacy banner',
    patterns: [/shopify-pc__banner/i, /consentTracking/i, /customerPrivacy/i, /privacyBanner/i],
  },
];

// Detect that the target is actually a Shopify storefront (soft signal only).
const SHOPIFY_SIGNALS = [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i, /\bShopify\.routes\b/i, /x-shopify/i];

function normalizeUrl(raw) {
  const trimmed = String(raw || '').trim();
  if (!trimmed) throw new ScanError('Please enter a store URL.', 400);
  let candidate = trimmed;
  if (!/^https?:\/\//i.test(candidate)) candidate = 'https://' + candidate;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new ScanError('That does not look like a valid web address.', 400);
  }
  assertSafeScheme(parsed);
  return parsed;
}

// Reject addresses that resolve into private / reserved ranges to prevent the
// scanner being used as an SSRF pivot into internal infrastructure.
function isBlockedIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true; // multicast / reserved
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80')) return true; // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique-local
    // IPv4-mapped (::ffff:a.b.c.d) — re-check the embedded v4 address.
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedIp(mapped[1]);
    return false;
  }
  return true; // unknown format -> block
}

async function assertPublicHost(hostname) {
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') || lower.endsWith('.local') || lower.endsWith('.internal')) {
    throw new ScanError('Internal or local addresses cannot be scanned.', 400);
  }
  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new ScanError('We could not resolve that domain. Check the spelling and try again.', 400);
  }
  if (!records.length) throw new ScanError('We could not resolve that domain.', 400);
  for (const { address } of records) {
    if (isBlockedIp(address)) {
      throw new ScanError('Internal or local addresses cannot be scanned.', 400);
    }
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 5;

// Validate scheme + port on a parsed URL. Throws ScanError if unsafe.
function assertSafeScheme(parsed) {
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ScanError('Only http and https addresses can be scanned.', 400);
  }
  if (parsed.port && !['', '80', '443'].includes(parsed.port)) {
    throw new ScanError('Only standard web ports (80/443) can be scanned.', 400);
  }
}

async function readCappedBody(res) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return text.slice(0, MAX_BYTES);
  }
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.length;
    if (received > MAX_BYTES) {
      try { await reader.cancel(); } catch { /* ignore */ }
      break;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Fetch the document following redirects MANUALLY, re-validating every hop.
// This is the SSRF defence: with redirect:'follow', undici would transparently
// follow a 302 into an internal IP before we ever saw it. By handling redirects
// ourselves we re-run assertPublicHost on each Location before requesting it.
async function fetchDocument(startUrl) {
  let current = startUrl; // caller has already validated the first hop's host

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(current.toString(), {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml' },
      });
    } catch (err) {
      if (err?.name === 'AbortError') throw new ScanError('The store took too long to respond.', 504);
      throw new ScanError('We could not reach that store. It may be password-protected or offline.', 502);
    } finally {
      clearTimeout(timer);
    }

    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get('location');
      if (!location) throw new ScanError('The store sent a broken redirect.', 502);
      let next;
      try {
        next = new URL(location, current);
      } catch {
        throw new ScanError('The store redirected to an invalid address.', 502);
      }
      assertSafeScheme(next);
      await assertPublicHost(next.hostname); // re-validate BEFORE following
      current = next;
      continue;
    }

    if (!res.ok) throw new ScanError(`The store responded with status ${res.status}.`, 502);

    const contentType = res.headers.get('content-type') || '';
    if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) {
      throw new ScanError('That address did not return a web page.', 415);
    }

    const html = await readCappedBody(res);
    return { html, finalUrl: current.toString() };
  }

  throw new ScanError('That store redirects too many times.', 502);
}

function collectHaystack(html) {
  const $ = cheerio.load(html);
  const parts = [];
  $('script').each((_, el) => {
    const src = $(el).attr('src');
    if (src) parts.push(src);
    const body = $(el).html();
    if (body) parts.push(body);
  });
  $('link[href]').each((_, el) => parts.push($(el).attr('href') || ''));
  $('iframe[src]').each((_, el) => parts.push($(el).attr('src') || ''));
  // Fall back to the whole document too — some pixels are injected via noscript
  // tags or data attributes.
  parts.push(html);
  return parts.join('\n');
}

function matchAll(list, haystack) {
  const hits = [];
  for (const item of list) {
    if (item.patterns.some((re) => re.test(haystack))) {
      hits.push({ key: item.key, name: item.name });
    }
  }
  return hits;
}

function buildVerdict(trackers, cmps, isShopify) {
  const findings = [];
  let score;
  let level;

  if (trackers.length > 0 && cmps.length === 0) {
    level = 'critical';
    // Trackers firing with no consent layer is a real violation — keep the
    // score in clearly-red territory so the number matches the verdict colour.
    score = Math.max(8, 46 - (trackers.length - 1) * 8);
    findings.push({
      severity: 'critical',
      title: 'Tracking scripts load with no consent banner',
      detail:
        `We detected ${trackers.length} tracking technolog${trackers.length === 1 ? 'y' : 'ies'} ` +
        'but no consent-management layer. Under GDPR/ePrivacy these scripts must not run ' +
        'until an EU visitor opts in. As loaded, they fire on page open.',
    });
  } else if (trackers.length > 0 && cmps.length > 0) {
    level = 'warning';
    score = Math.min(82, Math.max(62, 86 - trackers.length * 4));
    findings.push({
      severity: 'warning',
      title: 'Consent tool found — but blocking is unverified',
      detail:
        `A consent layer (${cmps.map((c) => c.name).join(', ')}) is present, yet ${trackers.length} ` +
        'tracker(s) are still embedded. Many setups load the banner but never actually block ' +
        'the scripts before consent. This needs a behavioural check.',
    });
  } else {
    level = 'good';
    score = 92;
    findings.push({
      severity: 'good',
      title: 'No common tracking pixels detected on load',
      detail:
        'We did not find the major advertising/analytics pixels firing on the homepage. ' +
        'Verify any tools loaded later in the funnel (checkout, account pages).',
    });
  }

  if (trackers.length > 0) {
    findings.push({
      severity: trackers.length >= 3 ? 'warning' : 'info',
      title: `${trackers.length} tracking technolog${trackers.length === 1 ? 'y' : 'ies'} identified`,
      detail: trackers.map((t) => t.name).join(' · '),
    });
  }
  if (!isShopify) {
    findings.push({
      severity: 'info',
      title: 'This may not be a Shopify store',
      detail:
        'We could not confirm Shopify signatures. The scan still works, but Consentry is built ' +
        'for Shopify storefronts.',
    });
  }

  return { score, level, findings };
}

export async function scanStore(rawUrl) {
  const url = normalizeUrl(rawUrl);
  await assertPublicHost(url.hostname);
  const { html, finalUrl } = await fetchDocument(url);
  const haystack = collectHaystack(html);

  const trackers = matchAll(TRACKERS, haystack);
  const cmps = matchAll(CMPS, haystack);
  const isShopify = SHOPIFY_SIGNALS.some((re) => re.test(haystack));
  const verdict = buildVerdict(trackers, cmps, isShopify);

  return {
    url: url.toString(),
    finalUrl,
    isShopify,
    trackers,
    cmps,
    ...verdict,
  };
}

export class ScanError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.name = 'ScanError';
    this.status = status;
  }
}
