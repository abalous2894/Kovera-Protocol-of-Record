import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';
import type { Ap2ConductSnapshot } from './ap2ConductReceipt.js';

/** Wave 11 Track E — Microsoft AGT / Agent Hooks audit ingest → AP2 conduct normalize. */

export const AGT_CONDUCT_RECEIPT_SCHEMA = 'aevesa.agt-conduct-receipt/v1' as const;

export type AgtSourceSchema =
  | 'microsoft.mcp-gateway.audit-entry/v1'
  | 'microsoft.agent365.audit/v1'
  | 'microsoft.agt.offline-receipt/v1';

export type AgtSourceVendor = 'microsoft_agt' | 'microsoft_agent365' | 'agent_hooks';

export interface AgtAuditEntryInput {
  agent_id: string;
  tool_name: string;
  allowed: boolean;
  correlation_id: string;
  policy_reference?: string | null;
  entry_hash?: string | null;
  mcp_server?: string | null;
  sensitivity_label?: string | null;
}

export interface AgtConductReceiptInput {
  organization_id: string;
  session_id: string;
  source_schema: AgtSourceSchema;
  source_vendor: AgtSourceVendor;
  ingested_at?: string;
  agt_audit: AgtAuditEntryInput;
}



/**
 * Normalize AGT audit entry to AP2 conduct snapshot (mandate_correlation_only lane).
 */
export function normalizeAgtToAp2Conduct(agtAudit: AgtAuditEntryInput): Ap2ConductSnapshot {
  const toolHopDigest = sha256HexUtf8(
    stableStringify({
      agent_id: String(agtAudit.agent_id || '').trim(),
      tool_name: String(agtAudit.tool_name || '').trim(),
      allowed: agtAudit.allowed === true,
      mcp_server: agtAudit.mcp_server ?? null,
    }),
  );
  const policyRef = String(agtAudit.policy_reference || '').trim();
  return {
    coverage: 'mandate_correlation_only',
    tool_hop_digests: [toolHopDigest],
    policy_digest: policyRef ? sha256HexUtf8(policyRef) : null,
    spend_cap: null,
    model_ref_digest: null,
    hitl_approval_digest: null,
  };
}

export function buildAgtConductReceiptPreimage(
  input: AgtConductReceiptInput & { ingested_at: string; normalized_ap2_conduct_digest: string },
): Record<string, unknown> {
  return {
    schema: AGT_CONDUCT_RECEIPT_SCHEMA,
    organization_id: String(input.organization_id || '').trim(),
    session_id: String(input.session_id || '').trim(),
    source_schema: input.source_schema,
    source_vendor: input.source_vendor,
    ingested_at: input.ingested_at,
    agt_audit: {
      agent_id: String(input.agt_audit.agent_id || '').trim(),
      tool_name: String(input.agt_audit.tool_name || '').trim(),
      allowed: input.agt_audit.allowed === true,
      correlation_id: String(input.agt_audit.correlation_id || '').trim(),
      policy_reference: input.agt_audit.policy_reference ?? null,
      entry_hash: input.agt_audit.entry_hash
        ? String(input.agt_audit.entry_hash).trim().toLowerCase()
        : null,
      mcp_server: input.agt_audit.mcp_server ?? null,
      sensitivity_label: input.agt_audit.sensitivity_label ?? null,
    },
    normalized_ap2_conduct_digest: input.normalized_ap2_conduct_digest,
  };
}

export function buildNormalizedAp2ConductDigest(agtAudit: AgtAuditEntryInput): string {
  const conduct = normalizeAgtToAp2Conduct(agtAudit);
  return sha256HexUtf8(
    stableStringify({
      schema: 'aevesa.ap2-conduct-normalized/v1',
      correlation_id: String(agtAudit.correlation_id || '').trim(),
      conduct,
    }),
  );
}

export function buildAgtConductReceiptDocument(input: AgtConductReceiptInput) {
  const ingested_at = input.ingested_at || new Date().toISOString();
  const normalized_ap2_conduct_digest = buildNormalizedAp2ConductDigest(input.agt_audit);
  const preimage = buildAgtConductReceiptPreimage({
    ...input,
    ingested_at,
    normalized_ap2_conduct_digest,
  });
  const receipt_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    receipt_digest,
  };
}

export default {
  AGT_CONDUCT_RECEIPT_SCHEMA,
  normalizeAgtToAp2Conduct,
  buildNormalizedAp2ConductDigest,
  buildAgtConductReceiptDocument,
};
