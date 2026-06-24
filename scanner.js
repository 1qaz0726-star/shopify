// scanner.js — compliance scan engine for Shopify storefronts.
// Performs a STATIC scan of a storefront's HTML: it detects (a) tracking
// technologies embedded on the page and (b) whether a consent-management layer
// is present. It flags the common GDPR failure mode — trackers embedded with no
// consent layer gating them. Because this is static (no JS execution), it
// reports what is *embedded*, not proven runtime execution order; the verdict
// copy and report say so explicitly.

import * as cheerio from 'cheerio';
import dns from 'node:dns/promises';
import net from 'node:net';
import { Agent } from 'undici';

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
// Matched against script src / link href hosts and known init globals only —
// NOT bare brand words anywhere in the HTML, which a competitor mention or blog
// post could trivially spoof into a false "consent layer present".
const CMPS = [
  { key: 'onetrust', name: 'OneTrust', patterns: [/cdn\.cookielaw\.org/i, /otSDKStub/i, /\bOptanon[A-Z]/] },
  { key: 'cookiebot', name: 'Cookiebot', patterns: [/consent\.cookiebot\.com/i] },
  { key: 'cookieyes', name: 'CookieYes', patterns: [/cdn-cookieyes\.com/i] },
  { key: 'termly', name: 'Termly', patterns: [/app\.termly\.io/i] },
  { key: 'iubenda', name: 'iubenda', patterns: [/cdn\.iubenda\.com/i] },
  { key: 'osano', name: 'Osano', patterns: [/cmp\.osano\.com/i] },
  { key: 'complianz', name: 'Complianz', patterns: [/complianz-gdpr/i, /cmplz_/i] },
  { key: 'pandectes', name: 'Pandectes GDPR', patterns: [/pandectes\.io/i, /cdn\.pandectes/i] },
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
    const lower = ip.toLowerCase().split('%')[0]; // strip zone id
    if (lower === '::1' || lower === '::') return true;
    if (/^fe[89ab]/.test(lower)) return true; // link-local fe80::/10 (fe80–febf)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique-local
    if (lower.startsWith('ff')) return true; // multicast
    if (lower.startsWith('64:ff9b')) return true; // NAT64 (well-known prefix)
    // IPv4-mapped / -embedded: ::ffff:a.b.c.d (dotted) or ::ffff:7f00:1 (hex).
    const mapped = lower.match(/::ffff:(.+)$/);
    if (mapped) {
      const tail = mapped[1];
      if (tail.includes('.')) return isBlockedIp(tail);
      const groups = tail.split(':');
      if (groups.length <= 2 && groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) {
        const hex = groups.map((g) => g.padStart(4, '0')).join('').padStart(8, '0');
        const v4 = [0, 2, 4, 6].map((i) => parseInt(hex.slice(i, i + 2), 16)).join('.');
        return isBlockedIp(v4);
      }
      return true; // unrecognised embedded form -> block
    }
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

// Validate scheme + credentials + port on a parsed URL. Throws ScanError if
// unsafe. Applied to the initial URL AND every redirect target.
function assertSafeScheme(parsed) {
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new ScanError('Only http and https addresses can be scanned.', 400);
  }
  if (parsed.username || parsed.password) {
    throw new ScanError('Remove the username/password from the URL and try again.', 400);
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
    const remaining = MAX_BYTES - received;
    if (value.length >= remaining) {
      // Keep exactly up to the cap from the final chunk, then stop — previously
      // the whole overflowing chunk was discarded, truncating well under MAX.
      chunks.push(value.subarray(0, remaining));
      try { await reader.cancel(); } catch { /* ignore */ }
      break;
    }
    chunks.push(value);
    received += value.length;
  }
  return Buffer.concat(chunks).toString('utf8');
}

// An undici dispatcher whose DNS resolution IS the SSRF check: the address we
// validate is the exact address the socket connects to. This closes the
// DNS-rebinding (TOCTOU) gap between a separate lookup() and the real
// connection, where a domain could resolve "public" during validation and
// "127.0.0.1" at connect time.
function createGuardedAgent() {
  return new Agent({
    connect: {
      lookup(hostname, options, callback) {
        dns
          .lookup(hostname, { all: true })
          .then((records) => {
            if (!records.length) {
              callback(Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' }));
              return;
            }
            for (const r of records) {
              if (isBlockedIp(r.address)) {
                callback(Object.assign(new Error('Blocked private address'), { code: 'EBLOCKEDADDR' }));
                return;
              }
            }
            if (options && options.all) {
              callback(null, records);
            } else {
              callback(null, records[0].address, records[0].family);
            }
          })
          .catch((err) => callback(err));
      },
    },
  });
}

function isBlockedConnectError(err) {
  let e = err;
  for (let i = 0; i < 5 && e; i++) {
    if (e.code === 'EBLOCKEDADDR') return true;
    e = e.cause;
  }
  return false;
}

// Fetch the document following redirects MANUALLY, re-validating every hop.
// Defence in depth: the guarded dispatcher pins/validates the connect IP, and
// we also re-check each redirect target's host before following it.
async function fetchDocument(startUrl) {
  let current = startUrl; // caller has already validated the first hop's host
  const agent = createGuardedAgent();
  try {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
      try {
        let res;
        try {
          res = await fetch(current.toString(), {
            redirect: 'manual',
            signal: controller.signal,
            dispatcher: agent,
            headers: { 'User-Agent': USER_AGENT, Accept: 'text/html,application/xhtml+xml' },
          });
        } catch (err) {
          if (err?.name === 'AbortError') throw new ScanError('The store took too long to respond.', 504);
          if (isBlockedConnectError(err)) throw new ScanError('Internal or local addresses cannot be scanned.', 400);
          throw new ScanError('We could not reach that store. It may be password-protected or offline.', 502);
        }

        if (REDIRECT_STATUSES.has(res.status)) {
          await res.body?.cancel().catch(() => {});
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

        if (!res.ok) {
          await res.body?.cancel().catch(() => {});
          throw new ScanError(`The store responded with status ${res.status}.`, 502);
        }

        const contentType = res.headers.get('content-type') || '';
        if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) {
          await res.body?.cancel().catch(() => {});
          throw new ScanError('That address did not return a web page.', 415);
        }

        // Body read stays inside the timer scope, so the timeout covers the
        // full download — not just the response headers (slowloris defence).
        // A timeout here aborts the stream; map that to 504 rather than 500.
        let html;
        try {
          html = await readCappedBody(res);
        } catch (err) {
          if (err?.name === 'AbortError') throw new ScanError('The store took too long to respond.', 504);
          throw new ScanError('We could not finish reading that store.', 502);
        }
        return { html, finalUrl: current.toString() };
      } finally {
        clearTimeout(timer);
      }
    }
    throw new ScanError('That store redirects too many times.', 502);
  } finally {
    await agent.close().catch(() => {});
  }
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
      title: 'Trackers embedded, and no consent layer detected',
      detail:
        `We found ${trackers.length} tracking technolog${trackers.length === 1 ? 'y' : 'ies'} ` +
        'embedded on the page and did not detect a known consent-management layer. Under ' +
        'GDPR/ePrivacy these must not run until an EU visitor opts in. If nothing is gating them, ' +
        'they likely load before consent — confirm with a runtime check. (A custom/uncommon ' +
        'consent tool may not be recognised by this static scan.)',
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
      title: 'No common tracking pixels detected on the homepage',
      detail:
        'We did not find the major advertising/analytics pixels embedded on the homepage. ' +
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
  findings.push({
    severity: 'info',
    title: 'How we scanned this',
    detail:
      'This is a static scan of the homepage HTML — it detects what is embedded, not proven ' +
      'runtime behaviour. It is informational, not legal advice.',
  });

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
