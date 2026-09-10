import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const EVIDENCE_RESURRECTION_BATCH_SCHEMA = 'aevesa.evidence-resurrection-batch/v1' as const;
export const EVIDENCE_RESURRECTION_ATTESTATION_MODE = 'resurrected' as const;
export const EVIDENCE_RESURRECTION_DEDUPE_KEY = 'gateway_decision_id' as const;

export type EvidenceResurrectionBatchSource = 'otlp_logs_export' | 'gateway_decisions';

export interface EvidenceResurrectionBatchInput {
  batch_id: string;
  organization_id: string;
  source: EvidenceResurrectionBatchSource;
  started_at: string;
  completed_at: string;
  decision_count: number;
  receipt_count: number;
  skipped_idempotent: number;
  error_count: number;
  receipt_entry_hashes: string[];
  receipt_ids?: string[];
  errors?: Array<{ gateway_decision_id: string; code: string; message: string }>;
}



/**
 * Deterministic batch manifest preimage — excludes manifest_digest.
 */
export function buildEvidenceResurrectionBatchPreimage(input: EvidenceResurrectionBatchInput): Record<string, unknown> {
  return {
    schema: EVIDENCE_RESURRECTION_BATCH_SCHEMA,
    batch_id: String(input.batch_id || '').trim(),
    organization_id: String(input.organization_id || '').trim(),
    source: input.source,
    started_at: input.started_at,
    completed_at: input.completed_at,
    dedupe_key: EVIDENCE_RESURRECTION_DEDUPE_KEY,
    decision_count: Number(input.decision_count) || 0,
    receipt_count: Number(input.receipt_count) || 0,
    skipped_idempotent: Number(input.skipped_idempotent) || 0,
    error_count: Number(input.error_count) || 0,
    attestation_mode: EVIDENCE_RESURRECTION_ATTESTATION_MODE,
    receipt_entry_hashes: [...(input.receipt_entry_hashes || [])].sort(),
    receipt_ids: [...(input.receipt_ids || [])].sort(),
    errors: [...(input.errors || [])].sort((a, b) =>
      String(a.gateway_decision_id).localeCompare(String(b.gateway_decision_id)),
    ),
  };
}

export function buildEvidenceResurrectionBatchDocument(input: EvidenceResurrectionBatchInput) {
  const preimage = buildEvidenceResurrectionBatchPreimage(input);
  const manifest_digest = sha256HexUtf8(stableStringify(preimage));
  return {
    ...preimage,
    manifest_digest,
  };
}
