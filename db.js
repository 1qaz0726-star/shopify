// db.js — lightweight file-based persistence for admin batch scans.
// Stores data as JSON; atomic write (temp-file rename) prevents corruption.
// On Render free tier the data resets on deploy — acceptable for MVP outreach.

import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH  = path.join(__dirname, 'consentry-scans.json');
const TMP_PATH = DB_PATH + '.tmp';

let _scans  = [];
let _nextId = 1;

if (existsSync(DB_PATH)) {
  try {
    const raw  = readFileSync(DB_PATH, 'utf8');
    const data = JSON.parse(raw);
    _scans  = data.scans  || [];
    _nextId = data.nextId || (_scans.length ? Math.max(..._scans.map((s) => s.id)) + 1 : 1);
  } catch {
    // Corrupted file — start fresh.
  }
}

function save() {
  const content = JSON.stringify({ scans: _scans, nextId: _nextId }, null, 2);
  writeFileSync(TMP_PATH, content, 'utf8');
  renameSync(TMP_PATH, DB_PATH); // atomic on POSIX; best-effort on Windows
}

export function insertScan(domain, score, trackers, hasConsentLayer) {
  const row = {
    id:               _nextId++,
    domain,
    score,
    trackers:         Array.isArray(trackers) ? trackers : [],
    has_consent_layer: !!hasConsentLayer,
    scanned_at:       new Date().toISOString(),
    email_status:     'pending',
  };
  _scans.push(row);
  save();
  return row;
}

export function listScans() {
  return [..._scans].sort((a, b) => (a.score ?? 999) - (b.score ?? 999));
}

export function setEmailStatus(id, status) {
  const scan = _scans.find((s) => s.id === id);
  if (scan) { scan.email_status = status; save(); }
}

export function removeScan(id) {
  _scans = _scans.filter((s) => s.id !== id);
  save();
}
