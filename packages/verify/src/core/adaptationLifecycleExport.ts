import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import { DECLARED_ADAPTATION_ENVELOPE_SCHEMA } from './declaredAdaptationEnvelope.js';
import { SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA } from './substantialModificationSignal.js';
import type { ComposedMemberRef } from './deployerLogCustodyPack.js';

/** Track P6 — adaptation lifecycle export (Problem 6 litigation / Art. 12 shaped). */

export const ADAPTATION_LIFECYCLE_EXPORT_SCHEMA =
  'aevesa.adaptation-lifecycle-export/v1' as const;

export const ADAPTATION_LIFECYCLE_EXPORT_SKU =
  'aevesa-adaptation-lifecycle-export-v1' as const;

export const ADAPTATION_DRIFT_WITNESS_TIMELINE_SCHEMA =
  'aevesa.adaptation-drift-witness-timeline/v1' as const;

export type LifecycleReadiness = 'export_ready' | 'partial' | 'incomplete';

export interface AdaptationDriftWitnessTimelineEntry {
  sequence_index: number;
  observed_at: string;
  drift_status: 'inside_envelope' | 'breach' | 'insufficient_snapshot';
  drift_code: string;
  witness_entry_hash?: string | null;
  runtime_snapshot_digest: string;
  breach_count?: number;
}

export interface AdaptationLifecycleWindow {
  started_at: string;
  ended_at: string;
}

export interface AdaptationLifecycleMemberDocuments {
  declared_adaptation_envelope: Record<string, unknown>;
  substantial_modification_signal?: Record<string, unknown>;
}

export interface AdaptationLifecycleAssertionsInput {
  third_party_verifiable: boolean;
}

export interface AdaptationLifecycleExportInput {
  organization_id: string;
  system_id: string;
  operator_role: 'provider' | 'deployer';
  generated_at?: string;
  lifecycle_window: AdaptationLifecycleWindow;
  drift_witness_timeline: AdaptationDriftWitnessTimelineEntry[];
  member_documents: AdaptationLifecycleMemberDocuments;
  composed_members: ComposedMemberRef[];
  lifecycle_assertions: AdaptationLifecycleAssertionsInput;
  ordered_witness_entry_hashes?: string[];
  disclaimer?: string;
}

function normalizeHex64(value: unknown): string | null {
  const s = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(s) ? s : null;
}

function sortHex64(values: string[] | undefined): string[] {
  return [...(values || [])]
    .map((v) => String(v || '').trim().toLowerCase())
    .filter((v) => /^[a-f0-9]{64}$/.test(v))
    .sort();
}

export function normalizeAdaptationDriftWitnessTimeline(
  entries: AdaptationDriftWitnessTimelineEntry[],
): Record<string, unknown>[] {
  return [...(entries || [])]
    .map((entry, idx) => ({
      sequence_index: Number(entry.sequence_index ?? idx),
      observed_at: String(entry.observed_at || '').trim(),
      drift_status: entry.drift_status,
      drift_code: String(entry.drift_code || '').trim(),
      witness_entry_hash: entry.witness_entry_hash
        ? normalizeHex64(entry.witness_entry_hash)
        : null,
      runtime_snapshot_digest:
        normalizeHex64(entry.runtime_snapshot_digest)
        || String(entry.runtime_snapshot_digest || '').trim().toLowerCase(),
      breach_count: entry.breach_count != null ? Number(entry.breach_count) : 0,
    }))
    .filter((e) => e.observed_at.length > 0 && e.runtime_snapshot_digest.length > 0)
    .sort((a, b) => a.sequence_index - b.sequence_index);
}

export function buildAdaptationDriftWitnessTimelineDigest(
  entries: AdaptationDriftWitnessTimelineEntry[],
): string {
  const normalized = normalizeAdaptationDriftWitnessTimeline(entries);
  return sha256HexUtf8(
    stableStringify({
      schema: ADAPTATION_DRIFT_WITNESS_TIMELINE_SCHEMA,
      entries: normalized,
    }),
  );
}

export function deriveLifecycleReadiness(input: {
  envelopeVerifyOk: boolean;
  timelineEntryCount: number;
  finalDriftStatus: string | null;
  signalPresent: boolean;
  signalVerifyOk: boolean;
  thirdPartyVerifiable: boolean;
}): LifecycleReadiness {
  if (!input.envelopeVerifyOk) return 'incomplete';
  if (input.timelineEntryCount === 0) return 'partial';
  const breachArc = input.finalDriftStatus === 'breach';
  if (breachArc && (!input.signalPresent || !input.signalVerifyOk)) return 'partial';
  if (
    input.envelopeVerifyOk
    && input.timelineEntryCount > 0
    && (!breachArc || (input.signalPresent && input.signalVerifyOk))
    && input.thirdPartyVerifiable
  ) {
    return 'export_ready';
  }
  if (input.envelopeVerifyOk && input.timelineEntryCount > 0) return 'partial';
  return 'incomplete';
}

export function buildLifecycleAssertionsBlock(
  input: AdaptationLifecycleAssertionsInput & {
    envelopeVerifyOk: boolean;
    timelineEntryCount: number;
    finalDriftStatus: string | null;
    signalPresent: boolean;
    signalVerifyOk: boolean;
  },
) {
  const lifecycle_readiness = deriveLifecycleReadiness({
    envelopeVerifyOk: input.envelopeVerifyOk,
    timelineEntryCount: input.timelineEntryCount,
    finalDriftStatus: input.finalDriftStatus,
    signalPresent: input.signalPresent,
    signalVerifyOk: input.signalVerifyOk,
    thirdPartyVerifiable: input.third_party_verifiable === true,
  });

  return {
    third_party_verifiable: input.third_party_verifiable === true,
    envelope_member_verified: input.envelopeVerifyOk,
    drift_timeline_present: input.timelineEntryCount > 0,
    breach_signal_present: input.signalPresent,
    breach_signal_verified: input.signalVerifyOk,
    lifecycle_readiness,
  };
}

export function buildAdaptationLifecycleExportPreimage(
  input: Omit<
    AdaptationLifecycleExportInput,
    'disclaimer' | 'member_documents' | 'lifecycle_assertions'
  > & {
    generated_at: string;
    lifecycle_assertions: ReturnType<typeof buildLifecycleAssertionsBlock>;
    drift_witness_timeline_digest: string;
  },
): Record<string, unknown> {
  const drift_witness_timeline = normalizeAdaptationDriftWitnessTimeline(input.drift_witness_timeline);
  const composed_members = [...input.composed_members]
    .map((m) => ({
      member_schema: String(m.member_schema || '').trim(),
      member_digest: String(m.member_digest || '').trim().toLowerCase(),
      verify_ok: m.verify_ok === true,
      label: String(m.label || '').trim(),
      entry_count: m.entry_count != null ? Number(m.entry_count) : null,
    }))
    .sort((a, b) => a.member_schema.localeCompare(b.member_schema));

  const ordered_witness_entry_hashes =
    input.ordered_witness_entry_hashes && input.ordered_witness_entry_hashes.length > 0
      ? sortHex64(input.ordered_witness_entry_hashes)
      : sortHex64(
          drift_witness_timeline.map((e) => String(e.witness_entry_hash || '')).filter(Boolean),
        );

  return {
    schema: ADAPTATION_LIFECYCLE_EXPORT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    system_id: String(input.system_id || '').trim(),
    operator_role: input.operator_role,
    generated_at: input.generated_at,
    lifecycle_window: {
      started_at: String(input.lifecycle_window.started_at || '').trim(),
      ended_at: String(input.lifecycle_window.ended_at || '').trim(),
    },
    drift_witness_timeline,
    drift_witness_timeline_digest: input.drift_witness_timeline_digest,
    composed_members,
    ordered_witness_entry_hashes,
    lifecycle_assertions: input.lifecycle_assertions,
  };
}

export interface AdaptationLifecycleExportDocument {
  schema: typeof ADAPTATION_LIFECYCLE_EXPORT_SCHEMA;
  organization_id: string;
  system_id: string;
  operator_role: 'provider' | 'deployer';
  generated_at: string;
  lifecycle_window: AdaptationLifecycleWindow;
  drift_witness_timeline: Record<string, unknown>[];
  drift_witness_timeline_digest: string;
  member_documents: AdaptationLifecycleMemberDocuments;
  composed_members: ComposedMemberRef[];
  ordered_witness_entry_hashes: string[];
  lifecycle_assertions: ReturnType<typeof buildLifecycleAssertionsBlock>;
  lifecycle_export_digest: string;
  disclaimer: string;
}

export function buildAdaptationLifecycleExportDocument(
  input: AdaptationLifecycleExportInput & {
    envelopeVerifyOk?: boolean;
    signalVerifyOk?: boolean;
  },
): AdaptationLifecycleExportDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const drift_witness_timeline_digest = buildAdaptationDriftWitnessTimelineDigest(
    input.drift_witness_timeline,
  );
  const envelopeDoc = input.member_documents.declared_adaptation_envelope;
  const signalDoc = input.member_documents.substantial_modification_signal;
  const timeline = normalizeAdaptationDriftWitnessTimeline(input.drift_witness_timeline);
  const finalEntry = timeline.length > 0 ? timeline[timeline.length - 1] : null;

  const lifecycle_assertions = buildLifecycleAssertionsBlock({
    ...input.lifecycle_assertions,
    envelopeVerifyOk: input.envelopeVerifyOk === true,
    timelineEntryCount: timeline.length,
    finalDriftStatus: finalEntry ? String(finalEntry.drift_status) : null,
    signalPresent: signalDoc != null,
    signalVerifyOk: input.signalVerifyOk === true,
  });

  const preimage = buildAdaptationLifecycleExportPreimage({
    organization_id: input.organization_id,
    system_id: input.system_id,
    operator_role: input.operator_role,
    generated_at,
    lifecycle_window: input.lifecycle_window,
    drift_witness_timeline: input.drift_witness_timeline,
    drift_witness_timeline_digest,
    composed_members: input.composed_members,
    ordered_witness_entry_hashes: input.ordered_witness_entry_hashes,
    lifecycle_assertions,
  });

  const lifecycle_export_digest = sha256HexUtf8(stableStringify(preimage));

  return {
    ...(preimage as Omit<
      AdaptationLifecycleExportDocument,
      'member_documents' | 'lifecycle_export_digest' | 'disclaimer'
    >),
    member_documents: {
      declared_adaptation_envelope: envelopeDoc,
      ...(signalDoc ? { substantial_modification_signal: signalDoc } : {}),
    },
    lifecycle_export_digest,
    disclaimer:
      input.disclaimer
      ?? 'Adaptation lifecycle export — Art. 12 / FRE 902(13) shaped evidence substrate; not legal advice or conformity certification.',
  };
}

export const ADAPTATION_LIFECYCLE_REQUIRED_MEMBER_SCHEMAS = [
  DECLARED_ADAPTATION_ENVELOPE_SCHEMA,
  ADAPTATION_DRIFT_WITNESS_TIMELINE_SCHEMA,
] as const;

export const ADAPTATION_LIFECYCLE_OPTIONAL_MEMBER_SCHEMAS = [
  SUBSTANTIAL_MODIFICATION_SIGNAL_SCHEMA,
] as const;
