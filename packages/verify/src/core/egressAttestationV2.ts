import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';
import {
  EGRESS_ATTESTATION_MODES,
  STANDARD_EGRESS_LIMITATIONS,
  buildEgressAttestationPreimage,
  type EgressAttestationInput,
  type EgressAttestationMode,
} from './egressAttestation.js';

/** Wave 17-A — pre-fetch run attribution for egress observe/intercept split (James J-1/J-2). */

export const EGRESS_ATTESTATION_V2_SCHEMA = 'aevesa.egress-attestation/v2' as const;
export const EGRESS_ATTESTATION_V2_SKU = 'aevesa-egress-attestation-v2' as const;

export const ATTRIBUTION_TIMING_VALUES = [
  'pre_fetch',
  'post_fetch',
  'runtime_only',
  'network_observe',
] as const;

export type AttributionTiming = (typeof ATTRIBUTION_TIMING_VALUES)[number];

export const STANDARD_EGRESS_V2_LIMITATIONS = [
  ...STANDARD_EGRESS_LIMITATIONS,
  'attribution_timing states whether egress was bound at network observe vs runtime — not a substitute for MCP PEP.',
  'Sandbox or egress proxy attributes observed channels; Aevesa notarizes the attestation digest offline.',
] as const;

export interface EgressAttestationV2Input extends EgressAttestationInput {
  run_id: string;
  intent_receipt_digest?: string | null;
  registry_manifest_digest?: string | null;
  attribution_timing: AttributionTiming;
}

export interface EgressAttestationV2Document {
  schema: typeof EGRESS_ATTESTATION_V2_SCHEMA;
  session_id: string;
  attestation_mode: EgressAttestationMode;
  mcp_pep_bound: boolean;
  proof_strength_disclosure_digest: string | null;
  observed_channels: string[];
  limitations: string[];
  generated_at: string;
  run_id: string;
  intent_receipt_digest: string | null;
  registry_manifest_digest: string | null;
  attribution_timing: AttributionTiming;
  attestation_digest: string;
}

function normalizeHexDigest(value: unknown): string | null {
  const digest = String(value ?? '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(digest) ? digest : null;
}

function normalizeLimitations(limitations?: string[]): string[] {
  const base =
    Array.isArray(limitations) && limitations.length
      ? limitations.map((item) => String(item).trim()).filter(Boolean)
      : [...STANDARD_EGRESS_V2_LIMITATIONS];
  return [...new Set(base)];
}

export function buildEgressAttestationV2Preimage(
  input: EgressAttestationV2Input & { generated_at: string },
): Omit<EgressAttestationV2Document, 'attestation_digest'> {
  const base = buildEgressAttestationPreimage({
    session_id: input.session_id,
    attestation_mode: input.attestation_mode,
    mcp_pep_bound: input.mcp_pep_bound,
    proof_strength_disclosure_digest: input.proof_strength_disclosure_digest ?? null,
    observed_channels: input.observed_channels ?? [],
    limitations: normalizeLimitations(input.limitations),
    generated_at: input.generated_at,
  });

  return {
    schema: EGRESS_ATTESTATION_V2_SCHEMA,
    session_id: base.session_id,
    attestation_mode: base.attestation_mode,
    mcp_pep_bound: base.mcp_pep_bound,
    proof_strength_disclosure_digest: base.proof_strength_disclosure_digest,
    observed_channels: base.observed_channels,
    limitations: base.limitations,
    generated_at: base.generated_at,
    run_id: String(input.run_id || '').trim(),
    intent_receipt_digest: normalizeHexDigest(input.intent_receipt_digest),
    registry_manifest_digest: normalizeHexDigest(input.registry_manifest_digest),
    attribution_timing: input.attribution_timing,
  };
}

export function buildEgressAttestationV2Document(
  input: EgressAttestationV2Input,
): EgressAttestationV2Document {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildEgressAttestationV2Preimage({ ...input, generated_at });
  const attestation_digest = sha256HexUtf8(stableStringify(preimage));
  return { ...preimage, attestation_digest };
}

export function includesAttributionTiming(value: unknown): value is AttributionTiming {
  return typeof value === 'string' && (ATTRIBUTION_TIMING_VALUES as readonly string[]).includes(value);
}

export function includesEgressMode(value: unknown): value is EgressAttestationMode {
  return typeof value === 'string' && (EGRESS_ATTESTATION_MODES as readonly string[]).includes(value);
}
