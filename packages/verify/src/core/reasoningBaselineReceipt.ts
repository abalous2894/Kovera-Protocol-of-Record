import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

/** Wave 9 Track O — Reasoning baseline receipt (institutional ontology hash + material decision pointers). */

export const REASONING_BASELINE_RECEIPT_SCHEMA = 'aevesa.reasoning-baseline-receipt/v1' as const;

export const REASONING_BASELINE_RECEIPT_SKU = 'aevesa-reasoning-baseline-receipt-v1' as const;

export const REASONING_BASELINE_KINDS = ['policy_ontology', 'institutional_playbook'] as const;

export type ReasoningBaselineKind = (typeof REASONING_BASELINE_KINDS)[number];

export const REASONING_REGULATORY_FRAMES = ['SR_11_7', 'ECOA', 'EU_AI_ACT', 'GENERIC'] as const;

export type ReasoningRegulatoryFrame = (typeof REASONING_REGULATORY_FRAMES)[number];

export const REASONING_DEVIATION_CLASSES = [
  'term_substitution',
  'policy_exception',
  'ontology_drift',
] as const;

export type ReasoningDeviationClass = (typeof REASONING_DEVIATION_CLASSES)[number];

export interface ReasoningBaselineSnapshot {
  baseline_id: string;
  baseline_kind: ReasoningBaselineKind;
  baseline_digest: string;
  ontology_version: string;
  regulatory_frame: ReasoningRegulatoryFrame | null;
  captured_at: string;
  term_set_digest: string | null;
}

export interface ReasoningMaterialDecisionDeviation {
  declared: boolean;
  deviation_class: ReasoningDeviationClass | null;
  deviation_digest: string | null;
  declared_term: string | null;
}

export interface ReasoningMaterialDecision {
  sequence: number;
  entry_hash: string;
  tool_name: string;
  decision_at: string;
  baseline_pointer: string;
  deviation: ReasoningMaterialDecisionDeviation;
}

export interface ReasoningBaselineVerifyManifest {
  offline_cli: string;
  portal_base: string;
  receipt_schema: string;
  csa_reasoning_gap_doc: string;
}

export interface ReasoningBaselineReceiptInput {
  session_id: string;
  organization_id: string;
  minted_at?: string;
  baseline: ReasoningBaselineSnapshot;
  material_decisions: ReasoningMaterialDecision[];
  receipt_entry_hashes?: string[];
  liability_receipt_profile?: 'PERMITTED' | 'DENIED' | 'HITL_RELEASED' | null;
  verify_manifest?: ReasoningBaselineVerifyManifest;
  non_goals?: string[];
}



export function computeTermSetDigest(terms: Record<string, unknown>): string {
  return sha256HexUtf8(stableStringify(terms));
}

export function buildReasoningBaselinePreimage(
  input: Pick<
    ReasoningBaselineReceiptInput,
    | 'session_id'
    | 'organization_id'
    | 'minted_at'
    | 'baseline'
    | 'material_decisions'
    | 'receipt_entry_hashes'
    | 'liability_receipt_profile'
    | 'verify_manifest'
    | 'non_goals'
  >,
): Record<string, unknown> {
  const baseline = input.baseline;
  const decisions = [...(input.material_decisions || [])].sort((a, b) => a.sequence - b.sequence);

  return {
    schema: REASONING_BASELINE_RECEIPT_SCHEMA,
    session_id: String(input.session_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    minted_at: input.minted_at || new Date(0).toISOString(),
    baseline: {
      baseline_id: String(baseline.baseline_id || '').trim(),
      baseline_kind:
        baseline.baseline_kind === 'institutional_playbook'
          ? 'institutional_playbook'
          : 'policy_ontology',
      baseline_digest: String(baseline.baseline_digest || '').trim().toLowerCase(),
      ontology_version: String(baseline.ontology_version || '').trim(),
      regulatory_frame: baseline.regulatory_frame ?? null,
      captured_at: String(baseline.captured_at || ''),
      term_set_digest:
        baseline.term_set_digest != null ? String(baseline.term_set_digest).trim().toLowerCase() : null,
    },
    material_decisions: decisions.map((d) => ({
      sequence: Number(d.sequence),
      entry_hash: String(d.entry_hash || '').trim().toLowerCase(),
      tool_name: String(d.tool_name || '').trim(),
      decision_at: String(d.decision_at || ''),
      baseline_pointer: String(d.baseline_pointer || '').trim().toLowerCase(),
      deviation: {
        declared: d.deviation?.declared === true,
        deviation_class: d.deviation?.declared
          ? d.deviation.deviation_class ?? null
          : null,
        deviation_digest:
          d.deviation?.declared && d.deviation.deviation_digest
            ? String(d.deviation.deviation_digest).trim().toLowerCase()
            : null,
        declared_term:
          d.deviation?.declared && d.deviation.declared_term
            ? String(d.deviation.declared_term).trim()
            : null,
      },
    })),
    receipt_entry_hashes: [...(input.receipt_entry_hashes || [])].sort(),
    liability_receipt_profile: input.liability_receipt_profile ?? null,
    verify_manifest: input.verify_manifest ?? null,
    non_goals: [...(input.non_goals || [])],
  };
}

export function buildReasoningBaselineReceiptDocument(input: ReasoningBaselineReceiptInput) {
  const minted_at = input.minted_at || new Date().toISOString();
  const preimage = buildReasoningBaselinePreimage({ ...input, minted_at });
  const receipt_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    minted_at,
    receipt_digest,
  };
}
