import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const INSURANCE_SIGNAL_DIGEST_SCHEMA = 'aevesa.insurance-signal-digest/v1' as const;

export interface InsuranceSignalDigestMetrics {
  hitl_coverage_pct: number | null;
  override_rate_pct: number | null;
  kill_switch_profile_ok: boolean;
  kill_switch_sla_ms: number | null;
  /** ISO timestamp of last verified shutdown drill (Track L6); null when no drill on record */
  kill_switch_drill_at: string | null;
  /** SHA-256 binding org + drill_id + bundle_digest; null when no drill on record */
  kill_switch_drill_freshness_digest: string | null;
  receipt_count: number;
  denied_receipt_count: number;
  ghost_score: number | null;
  witness_samples_ok: number;
  containment_events: number;
}

export interface InsuranceSignalDigestInput {
  organization_id: string;
  period_start: string;
  period_end: string;
  lookback_days: number;
  minted_at?: string;
  metrics: InsuranceSignalDigestMetrics;
  contributing_entry_hashes?: string[];
  digest_entry_hash?: string | null;
}



/**
 * Canonical metrics preimage — excludes digest_entry_hash and metrics_digest.
 */
export function buildInsuranceSignalMetricsPreimage(
  input: Pick<InsuranceSignalDigestInput, 'organization_id' | 'period_start' | 'period_end' | 'lookback_days' | 'minted_at' | 'metrics' | 'contributing_entry_hashes'>,
): Record<string, unknown> {
  const metrics = input.metrics;
  return {
    schema: INSURANCE_SIGNAL_DIGEST_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_start: String(input.period_start || '').trim(),
    period_end: String(input.period_end || '').trim(),
    lookback_days: Number(input.lookback_days) || 90,
    minted_at: input.minted_at || new Date(0).toISOString(),
    metrics: {
      hitl_coverage_pct: metrics.hitl_coverage_pct ?? null,
      override_rate_pct: metrics.override_rate_pct ?? null,
      kill_switch_profile_ok: metrics.kill_switch_profile_ok === true,
      kill_switch_sla_ms: metrics.kill_switch_sla_ms ?? null,
      kill_switch_drill_at: metrics.kill_switch_drill_at ?? null,
      kill_switch_drill_freshness_digest: metrics.kill_switch_drill_freshness_digest ?? null,
      receipt_count: Number(metrics.receipt_count) || 0,
      denied_receipt_count: Number(metrics.denied_receipt_count) || 0,
      ghost_score: metrics.ghost_score ?? null,
      witness_samples_ok: Number(metrics.witness_samples_ok) || 0,
      containment_events: Number(metrics.containment_events) || 0,
    },
    contributing_entry_hashes: [...(input.contributing_entry_hashes || [])].sort(),
  };
}

export function buildInsuranceSignalDigestDocument(input: InsuranceSignalDigestInput) {
  const minted_at = input.minted_at || new Date().toISOString();
  const preimage = buildInsuranceSignalMetricsPreimage({ ...input, minted_at });
  const metrics_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    digest_entry_hash: input.digest_entry_hash ?? null,
    metrics_digest,
  };
}
