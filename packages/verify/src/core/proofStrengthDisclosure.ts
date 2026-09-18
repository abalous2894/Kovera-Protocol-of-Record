import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Wave 15 Track A — explicit capture boundary for exported proof packages. */

export const PROOF_STRENGTH_DISCLOSURE_SCHEMA = 'aevesa.proof-strength-disclosure/v1' as const;
export const PROOF_STRENGTH_DISCLOSURE_SKU = 'aevesa-proof-strength-disclosure-v1' as const;
export const PEP_INVARIANT_RECEIPT_BEFORE_ACTION = 'receipt_before_action/v1' as const;

export const ENFORCEMENT_MODES = ['enforced', 'audit_only'] as const;
export type EnforcementMode = (typeof ENFORCEMENT_MODES)[number];

export const CAPTURE_TIMINGS = ['pre_execution', 'post_observed'] as const;
export type CaptureTiming = (typeof CAPTURE_TIMINGS)[number];

export const WITNESS_MODES = ['none', 'async', 'awaited_fail_closed'] as const;
export type WitnessMode = (typeof WITNESS_MODES)[number];

export const WITNESS_PERSISTENCE_LEVELS = ['postgres', 'memory_lab', 'external_only'] as const;
export type WitnessPersistence = (typeof WITNESS_PERSISTENCE_LEVELS)[number];

export const EXTERNAL_TRANSPARENCY_LEVELS = [
  'none',
  'rekor_metadata_only',
  'rekor_inclusion_verified',
] as const;
export type ExternalTransparency = (typeof EXTERNAL_TRANSPARENCY_LEVELS)[number];

export const STANDARD_PROOF_LIMITATIONS = [
  'Does not prove semantic truth or policy correctness.',
  'Does not prove universal capture or completeness of agent behavior.',
  'Cryptographic verification establishes integrity relative to the disclosed capture path only.',
] as const;

export interface ProofStrengthDisclosureInput {
  enforcement_mode: EnforcementMode;
  capture_timing: CaptureTiming;
  pep_invariant?: string | null;
  witness_mode: WitnessMode;
  witness_persistence: WitnessPersistence;
  external_transparency: ExternalTransparency;
  limitations?: string[];
  generated_at?: string;
}

export interface ProofStrengthCaptureContext {
  policy_enforcement_level?: string | null;
  pep_receipt_before_action_enabled?: boolean;
  pep_invariant?: string | null;
  witness_cosign_enabled?: boolean;
  witness_awaited?: boolean;
  witness_persistence?: WitnessPersistence;
  external_transparency?: ExternalTransparency;
  capture_timing?: CaptureTiming;
  generated_at?: string;
}

function normalizeLimitations(limitations: string[] | undefined): string[] {
  const base = Array.isArray(limitations) && limitations.length > 0
    ? limitations.map((item) => String(item).trim()).filter(Boolean)
    : [...STANDARD_PROOF_LIMITATIONS];
  return [...new Set(base)];
}

export function buildProofStrengthDisclosurePreimage(
  input: ProofStrengthDisclosureInput & { generated_at: string },
): Record<string, unknown> {
  return {
    schema: PROOF_STRENGTH_DISCLOSURE_SCHEMA,
    enforcement_mode: input.enforcement_mode,
    capture_timing: input.capture_timing,
    pep_invariant: input.pep_invariant ? String(input.pep_invariant).trim() : null,
    witness_mode: input.witness_mode,
    witness_persistence: input.witness_persistence,
    external_transparency: input.external_transparency,
    limitations: normalizeLimitations(input.limitations),
    generated_at: input.generated_at,
  };
}

export interface ProofStrengthDisclosureDocument {
  schema: typeof PROOF_STRENGTH_DISCLOSURE_SCHEMA;
  enforcement_mode: EnforcementMode;
  capture_timing: CaptureTiming;
  pep_invariant: string | null;
  witness_mode: WitnessMode;
  witness_persistence: WitnessPersistence;
  external_transparency: ExternalTransparency;
  limitations: string[];
  generated_at: string;
  disclosure_digest: string;
}

export function buildProofStrengthDisclosureDocument(
  input: ProofStrengthDisclosureInput,
): ProofStrengthDisclosureDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildProofStrengthDisclosurePreimage({ ...input, generated_at });
  const disclosure_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...(preimage as Omit<ProofStrengthDisclosureDocument, 'disclosure_digest'>),
    disclosure_digest,
  };
}

/**
 * Derive disclosure fields from runtime capture context (backend PEP / witness config).
 */
export function deriveProofStrengthDisclosureFromContext(
  ctx: ProofStrengthCaptureContext,
): ProofStrengthDisclosureDocument {
  const auditOnly = String(ctx.policy_enforcement_level || '').trim().toLowerCase() === 'audit_only';
  const pepEnabled = ctx.pep_receipt_before_action_enabled !== false;
  const pepInvariant = ctx.pep_invariant ?? (pepEnabled && !auditOnly ? PEP_INVARIANT_RECEIPT_BEFORE_ACTION : null);

  const enforcement_mode: EnforcementMode = auditOnly || !pepEnabled ? 'audit_only' : 'enforced';
  const capture_timing: CaptureTiming =
    ctx.capture_timing
    ?? (enforcement_mode === 'enforced' && pepInvariant === PEP_INVARIANT_RECEIPT_BEFORE_ACTION
      ? 'pre_execution'
      : 'post_observed');

  let witness_mode: WitnessMode = 'none';
  if (ctx.witness_cosign_enabled === true) {
    witness_mode = ctx.witness_awaited === true ? 'awaited_fail_closed' : 'async';
  }

  return buildProofStrengthDisclosureDocument({
    enforcement_mode,
    capture_timing,
    pep_invariant: pepInvariant,
    witness_mode,
    witness_persistence: ctx.witness_persistence ?? 'memory_lab',
    external_transparency: ctx.external_transparency ?? 'none',
    generated_at: ctx.generated_at,
  });
}
