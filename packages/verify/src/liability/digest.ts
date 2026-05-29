import { createHash } from 'node:crypto';
import { LIABILITY_RECEIPT_SCHEMA } from './types.js';

/** Canonical key order for receipt_digest (excludes integrity). */
export const RECEIPT_DIGEST_KEYS = [
  'schema',
  'receipt_id',
  'issued_at',
  'issuer',
  'session',
  'identity',
  'policy',
  'hitl',
  'side_effects',
  'proof',
  'diligence_summary',
] as const;

export function sha256HexUtf8(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * SHA-256 over stable JSON of accountability pillars (integrity excluded).
 * Matches liabilityReceiptV1Service.computeReceiptDigest.
 */
export function computeReceiptDigest(receipt: Record<string, unknown>): string {
  const body: Record<string, unknown> = {};
  for (const key of RECEIPT_DIGEST_KEYS) {
    if (receipt[key] !== undefined) {
      body[key] = receipt[key];
    }
  }
  return sha256HexUtf8(JSON.stringify(body));
}

export function assertSchemaId(receipt: Record<string, unknown>): string | null {
  if (receipt.schema !== LIABILITY_RECEIPT_SCHEMA) {
    return `schema must be "${LIABILITY_RECEIPT_SCHEMA}"`;
  }
  return null;
}
