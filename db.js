// db.js — Supabase-backed persistence for admin batch scans.

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY,
);

export async function insertScan({ domain, score, level, trackers, cmps, findings, hasConsentLayer }) {
  const { data, error } = await supabase
    .from('scans')
    .upsert(
      {
        domain,
        score,
        level:             level || 'unknown',
        trackers:          Array.isArray(trackers)  ? trackers  : [],
        cmps:              Array.isArray(cmps)      ? cmps      : [],
        findings:          Array.isArray(findings)  ? findings  : [],
        has_consent_layer: !!hasConsentLayer,
        scanned_at:        new Date().toISOString(),
        // email_status excluded → DB default 'pending' on insert; preserved on re-scan
      },
      { onConflict: 'domain' },
    )
    .select()
    .single();

  if (error) throw error;
  return data;
}

export async function listScans() {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .order('score', { ascending: true });

  if (error) throw error;
  return data || [];
}

export async function setEmailStatus(id, status) {
  const { error } = await supabase
    .from('scans')
    .update({ email_status: status })
    .eq('id', id);

  if (error) throw error;
}

export async function removeScan(id) {
  const { error } = await supabase
    .from('scans')
    .delete()
    .eq('id', id);

  if (error) throw error;
}
