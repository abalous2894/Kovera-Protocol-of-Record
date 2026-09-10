import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 12 Track D — Art. 72 / ISO 42001 post-market monitoring period snapshot. */

export const POST_MARKET_MONITORING_SNAPSHOT_SCHEMA =
  'aevesa.post-market-monitoring-snapshot/v1' as const;

export type MonitoringObligationStatus = 'met' | 'partial' | 'gap';

export interface Art72ObligationRow {
  obligation_id: string;
  label: string;
  status: MonitoringObligationStatus;
  evidence_ref: string;
  notes?: string | null;
}

export interface PostMarketMonitoringMetrics {
  agents_under_monitoring: number;
  material_sessions_observed: number;
  hitl_interventions: number;
  denied_actions: number;
  serious_incidents_in_period: number;
  shadow_agents_detected: number;
}

export interface PostMarketMonitoringSnapshotInput {
  organization_id: string;
  period_label: string;
  period_start: string;
  period_end: string;
  generated_at?: string;
  regulatory_framework?: string;
  monitoring_metrics: PostMarketMonitoringMetrics;
  art72_obligations: Art72ObligationRow[];
}



export function countObligationsByStatus(
  rows: Art72ObligationRow[],
  status: MonitoringObligationStatus,
): number {
  return (rows || []).filter((r) => r.status === status).length;
}

export type MonitoringReadiness = 'export_ready' | 'partial' | 'insufficient';

export function deriveMonitoringReadiness(
  obligations: Art72ObligationRow[],
  membersVerified: boolean,
): MonitoringReadiness {
  const gapCount = countObligationsByStatus(obligations, 'gap');
  const partialCount = countObligationsByStatus(obligations, 'partial');
  if (!membersVerified) return 'insufficient';
  if (gapCount > 0) return 'insufficient';
  if (partialCount > 0) return 'export_ready';
  return 'export_ready';
}

export function buildPostMarketMonitoringSnapshotPreimage(
  input: PostMarketMonitoringSnapshotInput & { generated_at: string },
): Record<string, unknown> {
  const obligations = [...(input.art72_obligations || [])]
    .map((r) => ({
      obligation_id: String(r.obligation_id || '').trim(),
      label: String(r.label || '').trim(),
      status: r.status,
      evidence_ref: String(r.evidence_ref || '').trim(),
      notes: r.notes != null ? String(r.notes).trim() : null,
    }))
    .sort((a, b) => a.obligation_id.localeCompare(b.obligation_id));

  const metrics = input.monitoring_metrics;

  return {
    schema: POST_MARKET_MONITORING_SNAPSHOT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    period_start: String(input.period_start || '').trim(),
    period_end: String(input.period_end || '').trim(),
    generated_at: input.generated_at,
    regulatory_framework: input.regulatory_framework || 'eu-ai-act-art72-iso42001',
    monitoring_metrics: {
      agents_under_monitoring: Number(metrics.agents_under_monitoring) || 0,
      material_sessions_observed: Number(metrics.material_sessions_observed) || 0,
      hitl_interventions: Number(metrics.hitl_interventions) || 0,
      denied_actions: Number(metrics.denied_actions) || 0,
      serious_incidents_in_period: Number(metrics.serious_incidents_in_period) || 0,
      shadow_agents_detected: Number(metrics.shadow_agents_detected) || 0,
    },
    art72_obligations: obligations,
    obligation_count: obligations.length,
    obligations_met_count: countObligationsByStatus(obligations, 'met'),
    obligations_partial_count: countObligationsByStatus(obligations, 'partial'),
    obligations_gap_count: countObligationsByStatus(obligations, 'gap'),
  };
}

export function buildPostMarketMonitoringSnapshotDocument(input: PostMarketMonitoringSnapshotInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildPostMarketMonitoringSnapshotPreimage({ ...input, generated_at });
  const snapshot_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    snapshot_digest,
  };
}

export default {
  POST_MARKET_MONITORING_SNAPSHOT_SCHEMA,
  buildPostMarketMonitoringSnapshotDocument,
  deriveMonitoringReadiness,
  countObligationsByStatus,
};
