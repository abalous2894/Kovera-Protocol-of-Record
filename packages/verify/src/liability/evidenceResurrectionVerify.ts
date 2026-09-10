import { sha256HexUtf8 } from '../core/sha256.js';
import { EVIDENCE_RESURRECTION_ATTESTATION_MODE, EVIDENCE_RESURRECTION_BATCH_SCHEMA, EVIDENCE_RESURRECTION_DEDUPE_KEY, buildEvidenceResurrectionBatchPreimage } from '../core/evidenceResurrection.js';
import { stableStringify } from '../core/stableStringify.js';

export const EVIDENCE_RESURRECTION_SKU = 'aevesa-evidence-resurrection-batch-v1' as const;

export interface EvidenceResurrectionBatchDocument {
  schema?: string;
  batch_id?: string;
  organization_id?: string;
  source?: string;
  started_at?: string;
  completed_at?: string;
  dedupe_key?: string;
  decision_count?: number;
  receipt_count?: number;
  skipped_idempotent?: number;
  error_count?: number;
  manifest_digest?: string;
  receipt_entry_hashes?: string[];
  receipt_ids?: string[];
  attestation_mode?: string;
  errors?: Array<{ gateway_decision_id: string; code: string; message: string }>;
}

export interface EvidenceResurrectionVerifyOptions {
  requireReceiptHashes?: boolean;
}

export interface EvidenceResurrectionVerifyResult {
  schema: typeof EVIDENCE_RESURRECTION_BATCH_SCHEMA;
  sku: typeof EVIDENCE_RESURRECTION_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    organizationIdPresent: boolean;
    batchIdPresent: boolean;
    dedupeKeyValid: boolean;
    attestationModeResurrected: boolean;
    manifestDigestMatches: boolean;
    receiptCountConsistent: boolean;
    profileComplete: boolean;
  };
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function verifyEvidenceResurrectionBatchBundle(
  input: unknown,
  options: EvidenceResurrectionVerifyOptions = {},
): EvidenceResurrectionVerifyResult {
  const doc = asRecord(input) as EvidenceResurrectionBatchDocument | null;
  const schemaValid = doc?.schema === EVIDENCE_RESURRECTION_BATCH_SCHEMA;
  const organizationIdPresent = String(doc?.organization_id || '').trim().length > 0;
  const batchIdPresent = String(doc?.batch_id || '').trim().length > 0;
  const dedupeKeyValid = doc?.dedupe_key === EVIDENCE_RESURRECTION_DEDUPE_KEY;
  const attestationModeResurrected = doc?.attestation_mode === EVIDENCE_RESURRECTION_ATTESTATION_MODE;

  const receiptHashes = Array.isArray(doc?.receipt_entry_hashes)
    ? doc!.receipt_entry_hashes.map(String)
    : [];
  const receiptCount = Number(doc?.receipt_count) || 0;
  const receiptCountConsistent =
    options.requireReceiptHashes === true ? receiptHashes.length === receiptCount : receiptHashes.length >= 0;

  let manifestDigestMatches = false;
  if (batchIdPresent && organizationIdPresent && doc?.started_at && doc?.completed_at) {
    const expected = sha256HexUtf8(
      stableStringify(
        buildEvidenceResurrectionBatchPreimage({
          batch_id: String(doc!.batch_id),
          organization_id: String(doc!.organization_id),
          source: (doc!.source as 'otlp_logs_export' | 'gateway_decisions') || 'gateway_decisions',
          started_at: String(doc!.started_at),
          completed_at: String(doc!.completed_at),
          decision_count: Number(doc!.decision_count) || 0,
          receipt_count: receiptCount,
          skipped_idempotent: Number(doc!.skipped_idempotent) || 0,
          error_count: Number(doc!.error_count) || 0,
          receipt_entry_hashes: receiptHashes,
          receipt_ids: Array.isArray(doc!.receipt_ids) ? doc!.receipt_ids.map(String) : [],
          errors: Array.isArray(doc!.errors) ? doc!.errors : [],
        }),
      ),
    );
    manifestDigestMatches = Boolean(doc!.manifest_digest) && doc!.manifest_digest === expected;
  }

  const profileComplete =
    schemaValid &&
    organizationIdPresent &&
    batchIdPresent &&
    dedupeKeyValid &&
    attestationModeResurrected &&
    manifestDigestMatches &&
    receiptCountConsistent;

  let note: string | null = null;
  if (profileComplete) {
    note = 'Evidence resurrection batch verified — manifest digest and resurrected attestation mode offline';
  } else if (!manifestDigestMatches) {
    note = 'manifest_digest does not match batch preimage';
  } else if (!attestationModeResurrected) {
    note = 'attestation_mode must be resurrected for historical backfill batches';
  } else if (!receiptCountConsistent) {
    note = 'receipt_entry_hashes length does not match receipt_count';
  } else {
    note = 'Evidence resurrection batch verification failed';
  }

  return {
    schema: EVIDENCE_RESURRECTION_BATCH_SCHEMA,
    sku: EVIDENCE_RESURRECTION_SKU,
    ok: profileComplete,
    checks: {
      schemaValid,
      organizationIdPresent,
      batchIdPresent,
      dedupeKeyValid,
      attestationModeResurrected,
      manifestDigestMatches,
      receiptCountConsistent,
      profileComplete,
    },
    gtmLine:
      'Platform logs expire with your contract. Resurrected receipts verify without Microsoft, Databricks, or Cyera.',
    note,
  };
}
