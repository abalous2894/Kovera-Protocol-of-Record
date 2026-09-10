import { sha256HexUtf8 } from '../core/sha256.js';
import { INSURANCE_SIGNAL_DIGEST_SCHEMA, buildInsuranceSignalMetricsPreimage } from '../core/insuranceSignalDigest.js';
import { stableStringify } from '../core/stableStringify.js';
import type { InsuranceSignalDigestMetrics } from '../core/insuranceSignalDigest.js';

export const INSURANCE_SIGNAL_DIGEST_SKU = 'aevesa-insurance-signal-digest-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address)$/i;

export interface InsuranceSignalDigestDocument {
  schema?: string;
  organization_id?: string;
  period_start?: string;
  period_end?: string;
  lookback_days?: number;
  minted_at?: string;
  metrics?: InsuranceSignalDigestMetrics;
  metrics_digest?: string;
  contributing_entry_hashes?: string[];
  digest_entry_hash?: string | null;
}

export interface InsuranceSignalDigestVerifyChecks {
  schemaValid: boolean;
  organizationIdPresent: boolean;
  periodValid: boolean;
  lookbackDaysValid: boolean;
  metricsDigestMatches: boolean;
  hashOnlySurface: boolean;
  profileComplete: boolean;
}

export interface InsuranceSignalDigestVerifyResult {
  schema: typeof INSURANCE_SIGNAL_DIGEST_SCHEMA;
  sku: typeof INSURANCE_SIGNAL_DIGEST_SKU;
  ok: boolean;
  checks: InsuranceSignalDigestVerifyChecks;
  gtmLine: string;
  note: string | null;
}

const HEX64 = /^[a-f0-9]{64}$/;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 6 || value == null) return false;
  if (Array.isArray(value)) {
    return value.some((v) => hasForbiddenKeys(v, depth + 1));
  }
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

/**
 * Verify insurance signal digest — hash-only recurring attest (no PII).
 */
export function verifyInsuranceSignalDigest(input: unknown): InsuranceSignalDigestVerifyResult {
  const doc = asRecord(input) as InsuranceSignalDigestDocument | null;
  const schemaValid = doc?.schema === INSURANCE_SIGNAL_DIGEST_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const period_start = String(doc?.period_start || '').trim();
  const period_end = String(doc?.period_end || '').trim();
  const periodValid =
    period_start.length > 0 &&
    period_end.length > 0 &&
    !Number.isNaN(Date.parse(period_start)) &&
    !Number.isNaN(Date.parse(period_end));
  const lookback_days = Number(doc?.lookback_days);
  const lookbackDaysValid = Number.isFinite(lookback_days) && lookback_days >= 7 && lookback_days <= 365;

  const metricsRaw = asRecord(doc?.metrics);
  const metrics = metricsRaw
    ? ({
        hitl_coverage_pct: metricsRaw.hitl_coverage_pct ?? null,
        override_rate_pct: metricsRaw.override_rate_pct ?? null,
        kill_switch_profile_ok: metricsRaw.kill_switch_profile_ok === true,
        kill_switch_sla_ms: metricsRaw.kill_switch_sla_ms ?? null,
        kill_switch_drill_at:
          metricsRaw.kill_switch_drill_at != null ? String(metricsRaw.kill_switch_drill_at) : null,
        kill_switch_drill_freshness_digest:
          metricsRaw.kill_switch_drill_freshness_digest != null
            ? String(metricsRaw.kill_switch_drill_freshness_digest)
            : null,
        receipt_count: Number(metricsRaw.receipt_count) || 0,
        denied_receipt_count: Number(metricsRaw.denied_receipt_count) || 0,
        ghost_score: metricsRaw.ghost_score ?? null,
        witness_samples_ok: Number(metricsRaw.witness_samples_ok) || 0,
        containment_events: Number(metricsRaw.containment_events) || 0,
      } as InsuranceSignalDigestMetrics)
    : null;
  const metricsPresent = metrics != null;

  let metricsDigestMatches = false;
  if (schemaValid && metricsPresent && doc) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildInsuranceSignalMetricsPreimage({
          organization_id: String(doc.organization_id),
          period_start,
          period_end,
          lookback_days,
          minted_at: String(doc.minted_at || ''),
          metrics: metrics as InsuranceSignalDigestMetrics,
          contributing_entry_hashes: Array.isArray(doc.contributing_entry_hashes)
            ? doc.contributing_entry_hashes.map(String)
            : [],
        }),
      ),
    );
    metricsDigestMatches = String(doc.metrics_digest || '') === expected;
  }

  const hashOnlySurface =
    !hasForbiddenKeys(doc) &&
    (doc?.contributing_entry_hashes || []).every((h) => HEX64.test(String(h)));

  const checks: InsuranceSignalDigestVerifyChecks = {
    schemaValid,
    organizationIdPresent,
    periodValid,
    lookbackDaysValid,
    metricsDigestMatches,
    hashOnlySurface,
    profileComplete:
      schemaValid &&
      organizationIdPresent &&
      periodValid &&
      lookbackDaysValid &&
      metricsPresent === true &&
      metricsDigestMatches &&
      hashOnlySurface,
  };

  const ok = checks.profileComplete;
  let note: string | null = null;
  if (!schemaValid) note = 'schema must be aevesa.insurance-signal-digest/v1';
  else if (!metricsDigestMatches) note = 'metrics_digest does not match canonical preimage';
  else if (!hashOnlySurface) note = 'forbidden PII-like keys or invalid entry hash format';

  return {
    schema: INSURANCE_SIGNAL_DIGEST_SCHEMA,
    sku: INSURANCE_SIGNAL_DIGEST_SKU,
    ok,
    checks,
    gtmLine:
      'Recurring bounded-autonomy telemetry for carriers — hash-only digest, offline verifiable.',
    note,
  };
}
