import { sha256HexUtf8 } from '../core/sha256.js';
import { POST_MARKET_MONITORING_SNAPSHOT_SCHEMA, buildPostMarketMonitoringSnapshotPreimage, countObligationsByStatus } from '../core/postMarketMonitoringSnapshot.js';
import { stableStringify } from '../core/stableStringify.js';
import type { Art72ObligationRow } from '../core/postMarketMonitoringSnapshot.js';

export const POST_MARKET_MONITORING_SNAPSHOT_SKU =
  'aevesa-post-market-monitoring-snapshot-v1' as const;

const FORBIDDEN_KEYS = /^(prompt|email|user_email|raw_payload|ssn|phone|address|pan|cvv)$/i;
const QUARTER_RE = /^\d{4}-Q[1-4]$/;

export interface PostMarketMonitoringSnapshotVerifyResult {
  schema: typeof POST_MARKET_MONITORING_SNAPSHOT_SCHEMA;
  sku: typeof POST_MARKET_MONITORING_SNAPSHOT_SKU;
  ok: boolean;
  checks: Record<string, boolean>;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function hasForbiddenKeys(value: unknown, depth = 0): boolean {
  if (depth > 8 || value == null) return false;
  if (Array.isArray(value)) return value.some((v) => hasForbiddenKeys(v, depth + 1));
  if (typeof value !== 'object') return false;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.test(key)) return true;
    if (hasForbiddenKeys(child, depth + 1)) return true;
  }
  return false;
}

export function verifyPostMarketMonitoringSnapshot(
  docInput: unknown,
): PostMarketMonitoringSnapshotVerifyResult {
  const doc = asRecord(docInput);
  const schemaValid = doc?.schema === POST_MARKET_MONITORING_SNAPSHOT_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const periodLabel = String(doc?.period_label || '').trim();
  const periodLabelValid = QUARTER_RE.test(periodLabel);
  const periodStartPresent = String(doc?.period_start || '').trim().length > 0;
  const periodEndPresent = String(doc?.period_end || '').trim().length > 0;

  const obligations = Array.isArray(doc?.art72_obligations)
    ? (doc.art72_obligations as Art72ObligationRow[])
    : [];
  const obligationsPresent = obligations.length >= 3;

  const metCount = countObligationsByStatus(obligations, 'met');
  const partialCount = countObligationsByStatus(obligations, 'partial');
  const gapCount = countObligationsByStatus(obligations, 'gap');
  const obligationCountsConsistent =
    Number(doc?.obligation_count) === obligations.length &&
    Number(doc?.obligations_met_count) === metCount &&
    Number(doc?.obligations_partial_count) === partialCount &&
    Number(doc?.obligations_gap_count) === gapCount;

  let snapshotDigestMatches = false;
  if (schemaValid && doc && obligationsPresent) {
    const metrics = asRecord(doc.monitoring_metrics) || {};
    const preimage = buildPostMarketMonitoringSnapshotPreimage({
      organization_id: String(doc.organization_id),
      period_label: periodLabel,
      period_start: String(doc.period_start),
      period_end: String(doc.period_end),
      generated_at: String(doc.generated_at || ''),
      regulatory_framework: String(doc.regulatory_framework || 'eu-ai-act-art72-iso42001'),
      monitoring_metrics: {
        agents_under_monitoring: Number(metrics.agents_under_monitoring) || 0,
        material_sessions_observed: Number(metrics.material_sessions_observed) || 0,
        hitl_interventions: Number(metrics.hitl_interventions) || 0,
        denied_actions: Number(metrics.denied_actions) || 0,
        serious_incidents_in_period: Number(metrics.serious_incidents_in_period) || 0,
        shadow_agents_detected: Number(metrics.shadow_agents_detected) || 0,
      },
      art72_obligations: obligations,
    });
    const expected = sha256HexUtf8(stableStringify(preimage));
    snapshotDigestMatches = String(doc.snapshot_digest || '').toLowerCase() === expected;
  }

  const hashOnlySurface = !hasForbiddenKeys(doc);

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    periodLabelValid &&
    periodStartPresent &&
    periodEndPresent &&
    obligationsPresent &&
    obligationCountsConsistent &&
    snapshotDigestMatches &&
    hashOnlySurface;

  let note: string | null = null;
  if (!schemaValid) note = `schema must be ${POST_MARKET_MONITORING_SNAPSHOT_SCHEMA}`;
  else if (!snapshotDigestMatches) note = 'snapshot_digest does not match canonical preimage';
  else if (!obligationCountsConsistent) note = 'obligation counts inconsistent with art72_obligations';

  return {
    schema: POST_MARKET_MONITORING_SNAPSHOT_SCHEMA,
    sku: POST_MARKET_MONITORING_SNAPSHOT_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      periodLabelValid,
      periodStartPresent,
      periodEndPresent,
      obligationsPresent,
      obligationCountsConsistent,
      snapshotDigestMatches,
      hashOnlySurface,
      profileComplete,
    },
    note,
  };
}
