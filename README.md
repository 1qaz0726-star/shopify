# Consentry — Phase 0 validation site

A free privacy/cookie compliance scanner for Shopify storefronts. A visitor pastes
their store URL; Consentry fetches the page, detects tracking pixels and whether a
consent layer gates them, and returns a plain-English compliance report. Goal of
Phase 0: **validate demand** before building the paid Shopify app.

## Run locally

```bash
npm install
npm start          # http://localhost:3000
# or: npm run dev  (auto-restart on file changes)
```

## How it works

- `server.js` — Express server. Serves `public/` and exposes `POST /api/scan`.
  Includes a per-IP rate limit and JSON body cap.
- `scanner.js` — the scan engine:
  - normalises and validates the URL,
  - **SSRF guard**: rejects private/reserved/link-local IPs and non-standard ports,
    re-checks the host after redirects,
  - fetches with a timeout + byte cap,
  - matches tracker / consent-management signatures and builds the verdict.
- `public/` — hand-built landing page (no framework). `app.js` renders the report
  with `textContent` only, so scanned URLs can't inject markup.

## Scope / honesty

This is a **static** scan of the homepage. It can detect that pixels are embedded
and that no consent layer is present, but it cannot prove runtime blocking behaviour
— the report says so. Not legal advice.

## Next (Phase 1)

If demand validates, graduate to an installable Shopify app (Remix template) whose
paid tier actually blocks trackers until consent and detects visitor region.
