import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import type { Ap2DisputeEvidenceInput } from './ap2DisputeThreatMap.js';

export const AP2_CONDUCT_RECEIPT_SCHEMA = 'aevesa.ap2-conduct-receipt/v1' as const;

export type Ap2ConductCoverage = 'mandate_correlation_only' | 'full_conduct';

export interface Ap2MandateRefs {
  correlation_id: string;
  intent_mandate_id?: string | null;
  cart_mandate_id?: string | null;
  payment_mandate_id?: string | null;
}

export interface Ap2SpendCapSnapshot {
  max_amount_minor: number | null;
  currency: string | null;
  /** SHA-256 of canonical spend-cap preimage — not a payment instrument */
  cap_digest: string | null;
}

export interface Ap2ConductSnapshot {
  coverage: Ap2ConductCoverage;
  tool_hop_digests: string[];
  policy_digest: string | null;
  spend_cap: Ap2SpendCapSnapshot | null;
  model_ref_digest: string | null;
  hitl_approval_digest: string | null;
}

export interface Ap2ConductReceiptInput {
  session_id: string;
  organization_id: string;
  minted_at?: string;
  mandate_refs: Ap2MandateRefs;
  conduct: Ap2ConductSnapshot;
  receipt_entry_hashes?: string[];
  liability_receipt_profile?: 'PERMITTED' | 'DENIED' | 'HITL_RELEASED' | null;
  dispute_evidence?: Ap2DisputeEvidenceInput | null;
}



/**
 * Canonical conduct preimage — excludes conduct_digest.
 */
export function buildAp2ConductPreimage(
  input: Pick<
    Ap2ConductReceiptInput,
    | 'session_id'
    | 'organization_id'
    | 'minted_at'
    | 'mandate_refs'
    | 'conduct'
    | 'receipt_entry_hashes'
    | 'liability_receipt_profile'
    | 'dispute_evidence'
  >,
): Record<string, unknown> {
  const conduct = input.conduct;
  const spend = conduct.spend_cap;
  const dispute = input.dispute_evidence;
  const preimage: Record<string, unknown> = {
    schema: AP2_CONDUCT_RECEIPT_SCHEMA,
    session_id: String(input.session_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    minted_at: input.minted_at || new Date(0).toISOString(),
    mandate_refs: {
      correlation_id: String(input.mandate_refs?.correlation_id || '').trim(),
      intent_mandate_id: input.mandate_refs?.intent_mandate_id ?? null,
      cart_mandate_id: input.mandate_refs?.cart_mandate_id ?? null,
      payment_mandate_id: input.mandate_refs?.payment_mandate_id ?? null,
    },
    conduct: {
      coverage: conduct.coverage === 'full_conduct' ? 'full_conduct' : 'mandate_correlation_only',
      tool_hop_digests: [...(conduct.tool_hop_digests || [])],
      policy_digest: conduct.policy_digest ?? null,
      spend_cap: spend
        ? {
            max_amount_minor: spend.max_amount_minor ?? null,
            currency: spend.currency ?? null,
            cap_digest: spend.cap_digest ?? null,
          }
        : null,
      model_ref_digest: conduct.model_ref_digest ?? null,
      hitl_approval_digest: conduct.hitl_approval_digest ?? null,
    },
    receipt_entry_hashes: [...(input.receipt_entry_hashes || [])].sort(),
    liability_receipt_profile: input.liability_receipt_profile ?? null,
  };

  if (dispute) {
    preimage.dispute_evidence = {
      analysis_ref: String(dispute.analysis_ref || '').trim(),
      threat_evaluation: [...(dispute.threat_evaluation || [])]
        .map((row) => ({
          threat_id: row.threat_id,
          label: row.label,
          status: row.status,
          aevesa_evidence_refs: [...(row.aevesa_evidence_refs || [])].sort(),
          notes: row.notes ?? null,
        }))
        .sort((a, b) => String(a.threat_id).localeCompare(String(b.threat_id))),
      dispute_readiness: dispute.dispute_readiness,
      portal_highlight_threat_ids: [...(dispute.portal_highlight_threat_ids || [])].sort(),
    };
  }

  return preimage;
}

export function buildAp2ConductReceiptDocument(input: Ap2ConductReceiptInput) {
  const minted_at = input.minted_at || new Date().toISOString();
  const preimage = buildAp2ConductPreimage({ ...input, minted_at });
  const conduct_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    conduct_digest,
  };
}
