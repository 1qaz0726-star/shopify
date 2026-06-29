import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const QUEUE_PATH = path.join(__dirname, 'scan-queue.json');
const TMP_PATH   = QUEUE_PATH + '.tmp';

let _queue = [];

if (existsSync(QUEUE_PATH)) {
  try { _queue = JSON.parse(readFileSync(QUEUE_PATH, 'utf8')) || []; } catch { _queue = []; }
}

function save() {
  writeFileSync(TMP_PATH, JSON.stringify(_queue, null, 2), 'utf8');
  renameSync(TMP_PATH, QUEUE_PATH);
}

export function addToQueue(domains) {
  const existing = new Set(_queue.map(q => q.domain));
  let added = 0;
  for (const raw of domains) {
    const domain = raw.toLowerCase().replace(/^www\./, '').trim();
    if (domain && !existing.has(domain)) {
      _queue.push({ domain, status: 'pending' });
      existing.add(domain);
      added++;
    }
  }
  if (added > 0) save();
  return added;
}

export function getNextBatch(n = 25) {
  const batch = _queue.filter(q => q.status === 'pending').slice(0, n);
  for (const item of batch) item.status = 'scanning';
  if (batch.length > 0) save();
  return batch.map(q => q.domain);
}

export function markDone(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '');
  const item = _queue.find(q => q.domain === d);
  if (item && item.status !== 'done') { item.status = 'done'; save(); }
}

export function getStats() {
  const total    = _queue.length;
  const done     = _queue.filter(q => q.status === 'done').length;
  const pending  = _queue.filter(q => q.status === 'pending').length;
  const scanning = _queue.filter(q => q.status === 'scanning').length;
  return { total, done, pending, scanning };
}

export function resetScanning() {
  let changed = false;
  for (const item of _queue) {
    if (item.status === 'scanning') { item.status = 'pending'; changed = true; }
  }
  if (changed) save();
}
