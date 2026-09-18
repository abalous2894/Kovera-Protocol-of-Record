import { sha256HexUtf8 } from './sha256.js';
import { stableStringify } from './stableStringify.js';

/** Phase 3 — honest split between MCP PEP path and egress/observe attestation (NIST logging transparency). */

export const EGRESS_ATTESTATION_SCHEMA = 'aevesa.egress-attestation/v1' as const;
export const EGRESS_ATTESTATION_SKU = 'aevesa-egress-attestation-v1' as const;

export const EGRESS_ATTESTATION_MODES = [
  'intercept_enforced',
  'observe_only',
  'egress_proxy_split',
] as const;

export type EgressAttestationMode = (typeof EGRESS_ATTESTATION_MODES)[number];

export const STANDARD_EGRESS_LIMITATIONS = [
  'Does not prove all egress channels were captured.',
  'MCP PEP proof_strength does not attest egress observe-only paths — bind this document separately.',
  'egress_proxy_split means intercept and observe paths are intentionally separated.',
] as const;

export interface EgressAttestationInput {
  session_id: string;
  attestation_mode: EgressAttestationMode;
  /** When false, document explicitly disclaims MCP PEP binding to egress path */
  mcp_pep_bound: boolean;
  proof_strength_disclosure_digest?: string | null;
  observed_channels?: string[];
  limitations?: string[];
  generated_at?: string;
}

export interface EgressAttestationDocument {
  schema: typeof EGRESS_ATTESTATION_SCHEMA;
  session_id: string;
  attestation_mode: EgressAttestationMode;
  mcp_pep_bound: boolean;
  proof_strength_disclosure_digest: string | null;
  observed_channels: string[];
  limitations: string[];
  generated_at: string;
  attestation_digest: string;
}

function normalizeLimitations(limitations?: string[]): string[] {
  const base =
    Array.isArray(limitations) && limitations.length
      ? limitations.map((item) => String(item).trim()).filter(Boolean)
      : [...STANDARD_EGRESS_LIMITATIONS];
  return [...new Set(base)];
}

export function buildEgressAttestationPreimage(
  input: EgressAttestationInput & { generated_at: string },
): Omit<EgressAttestationDocument, 'attestation_digest'> {
  return {
    schema: EGRESS_ATTESTATION_SCHEMA,
    session_id: String(input.session_id || '').trim(),
    attestation_mode: input.attestation_mode,
    mcp_pep_bound: input.mcp_pep_bound === true,
    proof_strength_disclosure_digest: input.proof_strength_disclosure_digest
      ? String(input.proof_strength_disclosure_digest).trim().toLowerCase()
      : null,
    observed_channels: (input.observed_channels ?? []).map((c) => String(c).trim()).filter(Boolean),
    limitations: normalizeLimitations(input.limitations),
    generated_at: input.generated_at,
  };
}

export function buildEgressAttestationDocument(
  input: EgressAttestationInput,
): EgressAttestationDocument {
  const generated_at = input.generated_at || new Date().toISOString();
  const preimage = buildEgressAttestationPreimage({ ...input, generated_at });
  const attestation_digest = sha256HexUtf8(stableStringify(preimage));
  return { ...preimage, attestation_digest };
}
