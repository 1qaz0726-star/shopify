// queue.js — Supabase-backed scan queue.

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
);

export async function addToQueue(domains) {
  if (!domains?.length) return 0;
  const rows = [...new Set(
    domains.map((d) => d.toLowerCase().replace(/^www\./, '').trim()).filter(Boolean),
  )].map((domain) => ({ domain, status: 'pending' }));
  if (!rows.length) return 0;

  const { data, error } = await supabase
    .from('scan_queue')
    .upsert(rows, { onConflict: 'domain', ignoreDuplicates: true })
    .select();

  if (error) throw error;
  return data?.length || 0;
}

export async function getNextBatch(n = 25) {
  const limit = Math.min(n, 25);

  const { data: pending } = await supabase
    .from('scan_queue')
    .select('domain')
    .eq('status', 'pending')
    .limit(limit);

  if (!pending?.length) return [];

  const domains = pending.map((r) => r.domain);

  await supabase
    .from('scan_queue')
    .update({ status: 'scanning' })
    .in('domain', domains);

  return domains;
}

export async function markDone(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '');
  await supabase
    .from('scan_queue')
    .update({ status: 'done' })
    .eq('domain', d);
}

export async function getStats() {
  const { data } = await supabase
    .from('scan_queue')
    .select('status');

  const rows = data || [];
  return {
    total:    rows.length,
    done:     rows.filter((r) => r.status === 'done').length,
    pending:  rows.filter((r) => r.status === 'pending').length,
    scanning: rows.filter((r) => r.status === 'scanning').length,
  };
}

export async function resetScanning() {
  await supabase
    .from('scan_queue')
    .update({ status: 'pending' })
    .eq('status', 'scanning');
}
