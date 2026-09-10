import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const CONFORMITY_CLOSURE_SCHEMA = 'aevesa.conformity-closure/v1' as const;

export interface ConformityClosureExportPack {
  type?: string;
  path?: string;
  label?: string;
}

export interface ConformityClosureEvaluateInput {
  obligation_id: string;
  organization_id: string;
  live_signal_count: number;
  signal_threshold: number;
  lookback_days: number;
  closure_test_id: string;
  export_pack?: ConformityClosureExportPack | null;
  gap_score_before?: number;
  contributing_entry_hashes?: string[];
  closed_at?: string;
  closure_entry_hash?: string | null;
}



/**
 * Deterministic closure preimage — excludes closure_entry_hash and closure_digest.
 */
export function buildConformityClosurePreimage(input: ConformityClosureEvaluateInput): Record<string, unknown> {
  return {
    schema: CONFORMITY_CLOSURE_SCHEMA,
    obligation_id: String(input.obligation_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    live_signal_count: Number(input.live_signal_count) || 0,
    signal_threshold: Number(input.signal_threshold) || 0,
    lookback_days: Number(input.lookback_days) || 90,
    closure_test_id: String(input.closure_test_id || '').trim(),
    gap_score_before: Number(input.gap_score_before) || 0,
    gap_score_after: 0,
    closed_at: input.closed_at || new Date(0).toISOString(),
    export_pack: input.export_pack ?? null,
    contributing_entry_hashes: [...(input.contributing_entry_hashes || [])].sort(),
  };
}

export function buildConformityClosureDocument(input: ConformityClosureEvaluateInput) {
  const closed_at = input.closed_at || new Date().toISOString();
  const preimage = buildConformityClosurePreimage({ ...input, closed_at });
  const closure_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    closure_entry_hash: input.closure_entry_hash ?? null,
    closure_digest,
  };
}

/**
 * Evaluate whether live signals meet closure threshold (pure — no I/O).
 */
export function evaluateConformityClosureSignals(input: {
  live_signal_count: number;
  signal_threshold: number;
  ledger_signals?: string[];
  signal_counts_by_type?: Record<string, number>;
}) {
  const live = Number(input.live_signal_count) || 0;
  const threshold = Math.max(1, Number(input.signal_threshold) || 1);
  const canClose = live >= threshold;
  const ledgerSignals = input.ledger_signals || [];
  const byType = input.signal_counts_by_type || {};
  const missingSignals = ledgerSignals.filter((sig) => (byType[sig] ?? 0) === 0);
  return {
    canClose,
    live_signal_count: live,
    signal_threshold: threshold,
    missingSignals: canClose ? [] : missingSignals,
    code: canClose ? 'CLOSURE_READY' : 'CLOSURE_SIGNALS_INSUFFICIENT',
  };
}
