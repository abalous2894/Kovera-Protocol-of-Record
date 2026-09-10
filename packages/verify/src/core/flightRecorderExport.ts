import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 9 Track M — ISO/IEC 24970-shaped session flight recorder export. */

export const FLIGHT_RECORDER_EXPORT_SCHEMA = 'aevesa.flight-recorder-export/v1' as const;

export const FLIGHT_RECORDER_EXPORT_SKU = 'aevesa-flight-recorder-export-v1' as const;

export const ISO24970_CROSSWALK_VERSION = 'fdis-2026-alignment-01' as const;

export const SCITT_AIR_PROFILE_REF = 'SCITT-AIR-draft-alignment-01' as const;

export const FLIGHT_RECORDER_EXPORT_PROFILES = ['hash_only', 'metadata_only'] as const;

export type FlightRecorderExportProfile = (typeof FLIGHT_RECORDER_EXPORT_PROFILES)[number];

export const FLIGHT_RECORDER_FORBIDDEN_CONTENT_KEYS = [
  'prompt',
  'content',
  'raw_payload',
  'user_message',
  'assistant_message',
  'message_body',
  'tool_output',
  'tool_input',
] as const;

export const FLIGHT_RECORDER_CROSSWALK_GAPS = [
  'GAP-24970-FDIS-PENDING',
  'GAP-NO-FULL-RECEIPT-BODY',
  'GAP-OPERATOR-OPTIONAL',
  'GAP-CONTENT-REF-OPTIONAL',
  'GAP-QUARTERLY-COMPOSITE-EXTERNAL',
] as const;

export interface FlightRecorderIso24970Event {
  timestamp: string;
  event_category: 'agent_action' | 'policy_decision' | 'human_oversight' | 'refusal' | 'governance';
  action: string;
  authorization_decision: string;
  tool_or_api: string | null;
  operator_attribution: string | null;
  agent_id: string | null;
  session_binding: string;
  content_ref_digest: string | null;
}

export interface FlightRecorderEventRow {
  sequence: number;
  entry_hash: string;
  issued_at: string;
  receipt_profile: string;
  iso24970: FlightRecorderIso24970Event;
  air_alignment_digest: string | null;
}

export interface FlightRecorderQuarterlyReviewHook {
  quarter: string | null;
  quarterly_export_digest: string | null;
  note: string;
}

export interface FlightRecorderVerifyManifest {
  offline_cli: string;
  portal_base: string;
  export_schema: string;
  iso24970_crosswalk_doc: string;
  scitt_air_profile_doc: string;
  quarterly_review_schema: string;
}

export interface FlightRecorderExportInput {
  organization_id: string;
  session_id: string;
  exported_at?: string;
  export_profile?: FlightRecorderExportProfile;
  iso24970_crosswalk_version?: string;
  scitt_air_profile?: string;
  events: FlightRecorderEventRow[];
  quarterly_review_hook?: FlightRecorderQuarterlyReviewHook;
  crosswalk_gaps?: string[];
  verify_manifest: FlightRecorderVerifyManifest;
  non_goals?: string[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}



function receiptProfileToCategory(profile: string): FlightRecorderIso24970Event['event_category'] {
  const p = String(profile || '').trim().toUpperCase();
  if (p === 'DENIED') return 'refusal';
  if (p === 'HITL_RELEASED' || p === 'HITL_PENDING') return 'human_oversight';
  if (p === 'PERMITTED') return 'agent_action';
  if (p.includes('GOVERNANCE')) return 'governance';
  return 'policy_decision';
}

/**
 * Map liability-receipt/v1 (or SCITT AIR-aligned receipt) to ISO 24970 logging element row.
 * Hash-only: never embeds prompt/content — only entry_hash + optional content_ref_digest.
 */
export function buildFlightRecorderEventFromReceipt(
  receipt: Record<string, unknown>,
  sequence: number,
  sessionId: string,
): FlightRecorderEventRow {
  const identity = asRecord(receipt.identity);
  const primaryActor = asRecord(identity?.primary_actor);
  const session = asRecord(receipt.session);
  const policy = asRecord(receipt.policy);
  const sideEffects = asRecord(receipt.side_effects);
  const action = asRecord(sideEffects?.action);
  const proof = asRecord(receipt.proof);
  const anchor = asRecord(proof?.primary_anchor);
  const hitl = asRecord(receipt.hitl);

  const entry_hash = String(anchor?.entry_hash || '').trim().toLowerCase();
  const issued_at = String(receipt.issued_at || new Date(0).toISOString());
  const receipt_profile = String(receipt.receipt_profile || 'PERMITTED').trim();

  const operator =
    hitl?.approver_sub ??
    hitl?.humanPrincipal ??
    primaryActor?.owner_user_id ??
    primaryActor?.principal_sub ??
    null;

  const contentDigestRaw =
    sideEffects?.content_ref_digest ??
    sideEffects?.payload_digest ??
    anchor?.content_digest ??
    null;
  const content_ref_digest =
    contentDigestRaw != null && String(contentDigestRaw).trim().length > 0
      ? String(contentDigestRaw).trim().toLowerCase()
      : null;

  const air = asRecord(receipt.air_alignment);
  const air_alignment_digest = air ? sha256HexUtf8(stableStringify(air)) : null;

  const iso24970: FlightRecorderIso24970Event = {
    timestamp: issued_at,
    event_category: receiptProfileToCategory(receipt_profile),
    action: String(action?.tool_name || action?.effect_class || receipt_profile || 'unknown'),
    authorization_decision: String(policy?.decision || receipt_profile || 'unknown'),
    tool_or_api: action?.tool_name != null ? String(action.tool_name) : null,
    operator_attribution: operator != null ? String(operator) : null,
    agent_id: primaryActor?.agent_id != null ? String(primaryActor.agent_id) : null,
    session_binding: String(session?.session_id || sessionId || '').trim(),
    content_ref_digest,
  };

  return {
    sequence: Number(sequence),
    entry_hash,
    issued_at,
    receipt_profile,
    iso24970,
    air_alignment_digest,
  };
}

function normalizeQuarterlyHook(
  hook: FlightRecorderQuarterlyReviewHook | undefined,
): FlightRecorderQuarterlyReviewHook {
  return {
    quarter: hook?.quarter != null ? String(hook.quarter).trim() : null,
    quarterly_export_digest:
      hook?.quarterly_export_digest != null
        ? String(hook.quarterly_export_digest).trim().toLowerCase()
        : null,
    note:
      hook?.note ||
      'Optional hook — digest references aevesa.quarterly-review-export/v1 without embedding duplicate crypto',
  };
}

function normalizeEvents(events: FlightRecorderEventRow[]): FlightRecorderEventRow[] {
  return [...events]
    .map((row, idx) => ({
      sequence: Number.isFinite(Number(row.sequence)) ? Number(row.sequence) : idx + 1,
      entry_hash: String(row.entry_hash || '').trim().toLowerCase(),
      issued_at: String(row.issued_at || ''),
      receipt_profile: String(row.receipt_profile || '').trim(),
      iso24970: {
        timestamp: String(row.iso24970?.timestamp || row.issued_at || ''),
        event_category: row.iso24970?.event_category || 'policy_decision',
        action: String(row.iso24970?.action || ''),
        authorization_decision: String(row.iso24970?.authorization_decision || ''),
        tool_or_api: row.iso24970?.tool_or_api != null ? String(row.iso24970.tool_or_api) : null,
        operator_attribution:
          row.iso24970?.operator_attribution != null
            ? String(row.iso24970.operator_attribution)
            : null,
        agent_id: row.iso24970?.agent_id != null ? String(row.iso24970.agent_id) : null,
        session_binding: String(row.iso24970?.session_binding || ''),
        content_ref_digest:
          row.iso24970?.content_ref_digest != null
            ? String(row.iso24970.content_ref_digest).trim().toLowerCase()
            : null,
      },
      air_alignment_digest:
        row.air_alignment_digest != null
          ? String(row.air_alignment_digest).trim().toLowerCase()
          : null,
    }))
    .sort((a, b) => a.sequence - b.sequence);
}

/**
 * Canonical export preimage — excludes export_digest and full receipt bodies.
 */
export function buildFlightRecorderExportPreimage(input: FlightRecorderExportInput): Record<string, unknown> {
  const events = normalizeEvents(input.events);
  return {
    schema: FLIGHT_RECORDER_EXPORT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    exported_at: input.exported_at || new Date(0).toISOString(),
    export_profile: input.export_profile || 'hash_only',
    iso24970_crosswalk_version: input.iso24970_crosswalk_version || ISO24970_CROSSWALK_VERSION,
    scitt_air_profile: input.scitt_air_profile || SCITT_AIR_PROFILE_REF,
    event_count: events.length,
    events,
    quarterly_review_hook: normalizeQuarterlyHook(input.quarterly_review_hook),
    crosswalk_gaps: [...(input.crosswalk_gaps ?? [])].sort(),
    verify_manifest: input.verify_manifest,
    non_goals: input.non_goals ?? [],
  };
}

export function buildFlightRecorderExportDocument(input: FlightRecorderExportInput) {
  const exported_at = input.exported_at || new Date().toISOString();
  const preimage = buildFlightRecorderExportPreimage({ ...input, exported_at });
  const export_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    exported_at,
    export_digest,
  };
}
