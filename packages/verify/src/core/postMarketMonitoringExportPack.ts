import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import {
  deriveMonitoringReadiness,
  type MonitoringReadiness,
} from './postMarketMonitoringSnapshot.js';

/** Wave 12 Track D — Art. 72 post-market monitoring export bound to conduct + census evidence. */

export const POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA =
  'aevesa.post-market-monitoring-export-pack/v1' as const;

export interface ComposedMonitoringMemberRef {
  member_schema: string;
  member_digest: string;
  verify_ok: boolean;
  label: string;
  entry_count?: number | null;
}

export interface MonitoringAssertionsInput {
  period_complete: boolean;
  conduct_evidence_bound: boolean;
  census_inventory_bound: boolean;
  iso42001_shape_valid: boolean;
  third_party_verifiable: boolean;
}

export interface MonitoringSessionBinding {
  period_label: string;
  snapshot_digest: string;
  census_pack_digest: string;
  conduct_manifest_digest: string;
  normalization_bound: boolean;
}

export interface PostMarketMonitoringExportPackInput {
  organization_id: string;
  period_label: string;
  generated_at?: string;
  monitoring_assertions: MonitoringAssertionsInput;
  composed_members: ComposedMonitoringMemberRef[];
  monitoring_session_binding: MonitoringSessionBinding;
  post_market_monitoring_snapshot: {
    snapshot_digest: string;
    period_start: string;
    period_end: string;
    obligation_count: number;
    obligations_met_count: number;
    obligations_partial_count: number;
  };
  disclaimer?: string;
}



export function buildMonitoringAssertionsBlock(
  input: MonitoringAssertionsInput,
  members: ComposedMonitoringMemberRef[],
  obligationGapCount: number,
  obligationPartialCount: number,
) {
  const censusOk = members.some(
    (m) => m.member_schema === 'aevesa.agent-census-completeness-pack/v1' && m.verify_ok === true,
  );
  const conductOk = members.some(
    (m) => m.member_schema === 'aevesa.traceable-conduct-manifest/v1' && m.verify_ok === true,
  );
  const snapshotOk = members.some(
    (m) => m.member_schema === 'aevesa.post-market-monitoring-snapshot/v1' && m.verify_ok === true,
  );
  const membersVerified = snapshotOk && censusOk && conductOk;

  let readiness: MonitoringReadiness = 'insufficient';
  if (membersVerified && obligationGapCount === 0) {
    readiness = obligationPartialCount > 0 ? 'export_ready' : 'export_ready';
  } else if (snapshotOk && (censusOk || conductOk)) {
    readiness = 'partial';
  }

  return {
    period_complete: input.period_complete === true,
    conduct_evidence_bound: conductOk || input.conduct_evidence_bound === true,
    census_inventory_bound: censusOk || input.census_inventory_bound === true,
    iso42001_shape_valid: input.iso42001_shape_valid === true && snapshotOk,
    third_party_verifiable: input.third_party_verifiable === true,
    monitoring_readiness: readiness,
    obligation_gap_count: obligationGapCount,
    obligation_partial_count: obligationPartialCount,
  };
}

export function buildPostMarketMonitoringExportPackPreimage(
  input: Omit<PostMarketMonitoringExportPackInput, 'disclaimer'> & {
    generated_at: string;
    monitoring_assertions: ReturnType<typeof buildMonitoringAssertionsBlock>;
    composed_members: ComposedMonitoringMemberRef[];
  },
): Record<string, unknown> {
  const members = [...(input.composed_members || [])]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const binding = input.monitoring_session_binding;
  const snapshot = input.post_market_monitoring_snapshot;

  return {
    schema: POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    period_label: String(input.period_label || '').trim(),
    generated_at: input.generated_at,
    monitoring_assertions: input.monitoring_assertions,
    post_market_monitoring_snapshot: {
      snapshot_digest: String(snapshot.snapshot_digest || '').trim().toLowerCase(),
      period_start: String(snapshot.period_start || '').trim(),
      period_end: String(snapshot.period_end || '').trim(),
      obligation_count: Number(snapshot.obligation_count) || 0,
      obligations_met_count: Number(snapshot.obligations_met_count) || 0,
      obligations_partial_count: Number(snapshot.obligations_partial_count) || 0,
    },
    composed_members: members,
    monitoring_session_binding: {
      period_label: String(binding.period_label || '').trim(),
      snapshot_digest: String(binding.snapshot_digest || '').trim().toLowerCase(),
      census_pack_digest: String(binding.census_pack_digest || '').trim().toLowerCase(),
      conduct_manifest_digest: String(binding.conduct_manifest_digest || '').trim().toLowerCase(),
      normalization_bound: binding.normalization_bound === true,
    },
  };
}

export function buildPostMarketMonitoringExportPackDocument(input: PostMarketMonitoringExportPackInput) {
  const generated_at = input.generated_at || new Date().toISOString();
  const gapCount =
    input.post_market_monitoring_snapshot.obligation_count -
    input.post_market_monitoring_snapshot.obligations_met_count -
    input.post_market_monitoring_snapshot.obligations_partial_count;
  const monitoring_assertions = buildMonitoringAssertionsBlock(
    input.monitoring_assertions,
    input.composed_members,
    Math.max(0, gapCount),
    input.post_market_monitoring_snapshot.obligations_partial_count ?? 0,
  );

  const preimage = buildPostMarketMonitoringExportPackPreimage({
    ...input,
    generated_at,
    monitoring_assertions,
    composed_members: input.composed_members,
  });
  const pack_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    pack_digest,
    disclaimer:
      input.disclaimer ||
      'Post-market monitoring export for diligence — not legal advice or regulatory submission.',
  };
}

export type { MonitoringReadiness };

export default {
  POST_MARKET_MONITORING_EXPORT_PACK_SCHEMA,
  buildMonitoringAssertionsBlock,
  buildPostMarketMonitoringExportPackDocument,
};
