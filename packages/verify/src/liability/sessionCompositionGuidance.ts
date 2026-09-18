import type { ChainEnforcementRollupResult } from './chainEnforcementRollup.js';
import type { SessionProofExportHints } from './sessionProofExportHints.js';
import { EGRESS_ATTESTATION_V2_SCHEMA } from '../core/egressAttestationV2.js';

export const SESSION_COMPOSITION_GUIDANCE_SCHEMA = 'aevesa.session-composition-guidance/v1' as const;
export const SESSION_COMPOSITION_GUIDANCE_SKU = 'aevesa-session-composition-guidance-v1' as const;

export const OWASP_ASI_GL3_HINT =
  'OWASP ASI GL3 (multi-agent governance): session exports must disclose per-hop enforcement and weakest-link — set complete ≠ uniformly enforced across the chain.';

export const OWASP_AT7_HINT =
  'OWASP AT7 (tool/session alignment): maintain a session register with per-hop enforcement_mode; audit_only middle hops break uniform pre-execution reliance.';

export const CARRIER_CHAIN_FOOTNOTE =
  'Carrier/MGA review: evaluate chain_enforcement_mode separately from terminal receipt proof_strength — MCP PEP path does not attest egress observe-only paths.';

export interface SessionCompositionGuidance {
  schema: typeof SESSION_COMPOSITION_GUIDANCE_SCHEMA;
  sku: typeof SESSION_COMPOSITION_GUIDANCE_SKU;
  owasp_asi_gl3_hint: string;
  owasp_at7_hint: string;
  carrier_footnote: string;
  chain_enforcement_mode: string | null;
  uniformly_enforced: boolean | null;
  weakest_link_index: number | null;
  require_member_receipt_verification: boolean;
  proof_trace_footnote: string;
}

export interface SessionCompositionGuidanceInput {
  chain_enforcement?: ChainEnforcementRollupResult | null;
  export_hints?: SessionProofExportHints | null;
}

function proofTraceFootnote(
  chain: ChainEnforcementRollupResult | null | undefined,
  requireMembers: boolean,
): string {
  const mode = chain?.chain_enforcement_mode ?? 'unknown';
  if (requireMembers) {
    return `Session manifest verified — ${OWASP_AT7_HINT} Bundle member_receipts[] or verify each hop digest independently.`;
  }
  if (mode === 'mixed' && chain?.weakest_link_index != null) {
    return `Mixed enforcement — weakest link hop ${chain.weakest_link_index} audit_only. ${OWASP_ASI_GL3_HINT}`;
  }
  if (mode === 'audit_only') {
    return `Audit-only chain — do not treat as uniformly pre-execution enforced. ${CARRIER_CHAIN_FOOTNOTE}`;
  }
  if (chain?.uniformly_enforced === true) {
    return `Uniformly enforced chain disclosed — still verify each member receipt independently for M&A/carrier submission.`;
  }
  return `${OWASP_ASI_GL3_HINT} ${OWASP_AT7_HINT}`;
}

/**
 * Buyer-facing GL3/AT7 composition hints for session exports and proof trace footnotes.
 */
export function buildSessionCompositionGuidance(
  input: SessionCompositionGuidanceInput,
): SessionCompositionGuidance {
  const chain = input.chain_enforcement ?? null;
  const requireMembers = input.export_hints?.require_member_receipt_verification === true;

  return {
    schema: SESSION_COMPOSITION_GUIDANCE_SCHEMA,
    sku: SESSION_COMPOSITION_GUIDANCE_SKU,
    owasp_asi_gl3_hint: OWASP_ASI_GL3_HINT,
    owasp_at7_hint: OWASP_AT7_HINT,
    carrier_footnote: CARRIER_CHAIN_FOOTNOTE,
    chain_enforcement_mode: chain?.chain_enforcement_mode ?? null,
    uniformly_enforced: chain?.uniformly_enforced ?? null,
    weakest_link_index: chain?.weakest_link_index ?? null,
    require_member_receipt_verification: requireMembers,
    proof_trace_footnote: proofTraceFootnote(chain, requireMembers),
  };
}

export function buildCarrierChainCompositionDisclosure(
  input: SessionCompositionGuidanceInput,
): Record<string, unknown> {
  const guidance = buildSessionCompositionGuidance(input);
  return {
    chain_enforcement_mode: guidance.chain_enforcement_mode ?? 'unknown',
    uniformly_enforced: guidance.uniformly_enforced === true,
    weakest_link_index: guidance.weakest_link_index,
    owasp_asi_gl3_hint: guidance.owasp_asi_gl3_hint,
    owasp_at7_hint: guidance.owasp_at7_hint,
    carrier_footnote: guidance.carrier_footnote,
    egress_attestation_schema: EGRESS_ATTESTATION_V2_SCHEMA,
  };
}
