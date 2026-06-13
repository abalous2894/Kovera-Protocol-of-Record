import { createHash } from 'node:crypto';
import { canonicalizeCausalLineageForDigest } from '../core/causalLineage.js';
import { canonicalizeIntentAlignmentForDigest } from '../core/intentAlignment.js';
import { LIABILITY_RECEIPT_SCHEMA } from './types.js';

/** Current normative pillar order (KVR-102 intent_alignment + KVR-301 causal_lineage when present). */
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
  'intent_context',
  'intent_alignment',
  'causal_lineage',
  'proof',
  'diligence_summary',
] as const;

/** Pre–intent_context receipts (legacy verify profile). */
export const RECEIPT_DIGEST_KEYS_V1_0 = [
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

/** KVR-101: intent_context in digest, advisory intent_alignment not yet bound. */
export const RECEIPT_DIGEST_KEYS_V1_INTENT_CONTEXT = [
  'schema',
  'receipt_id',
  'issued_at',
  'issuer',
  'session',
  'identity',
  'policy',
  'hitl',
  'side_effects',
  'intent_context',
  'proof',
  'diligence_summary',
] as const;

export type ReceiptDigestProfile = 'current' | 'v1_intent_context' | 'v1_0';

export const RECEIPT_DIGEST_PROFILE_ORDER: ReceiptDigestProfile[] = [
  'current',
  'v1_intent_context',
  'v1_0',
];

export function receiptDigestKeysForProfile(profile: ReceiptDigestProfile): readonly string[] {
  switch (profile) {
    case 'v1_0':
      return RECEIPT_DIGEST_KEYS_V1_0;
    case 'v1_intent_context':
      return RECEIPT_DIGEST_KEYS_V1_INTENT_CONTEXT;
    default:
      return RECEIPT_DIGEST_KEYS;
  }
}

export function sha256HexUtf8(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

function digestValueForKey(receipt: Record<string, unknown>, key: string): unknown {
  if (receipt[key] === undefined) return undefined;
  if (key === 'intent_alignment') {
    return canonicalizeIntentAlignmentForDigest(receipt[key]);
  }
  if (key === 'causal_lineage') {
    return canonicalizeCausalLineageForDigest(receipt[key]);
  }
  return receipt[key];
}

/**
 * SHA-256 over stable JSON of accountability pillars (integrity excluded).
 */
export function computeReceiptDigest(
  receipt: Record<string, unknown>,
  options: { profile?: ReceiptDigestProfile } = {},
): string {
  const keys = receiptDigestKeysForProfile(options.profile ?? 'current');
  const body: Record<string, unknown> = {};
  for (const key of keys) {
    const value = digestValueForKey(receipt, key);
    if (value !== undefined) {
      body[key] = value;
    }
  }
  return sha256HexUtf8(JSON.stringify(body));
}

export interface ReceiptDigestVerifyResult {
  ok: boolean;
  profile?: ReceiptDigestProfile;
  recomputed?: string;
}

/**
 * Verify stored receipt_digest against current and legacy preimage profiles.
 */
export function verifyReceiptDigestMatch(receipt: Record<string, unknown>): ReceiptDigestVerifyResult {
  const stored = String(
    receipt?.integrity && typeof receipt.integrity === 'object'
      ? (receipt.integrity as Record<string, unknown>).receipt_digest
      : '',
  )
    .trim()
    .toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(stored)) {
    return { ok: false };
  }

  for (const profile of RECEIPT_DIGEST_PROFILE_ORDER) {
    const recomputed = computeReceiptDigest(receipt, { profile });
    if (recomputed === stored) {
      return { ok: true, profile, recomputed };
    }
  }
  return { ok: false, recomputed: computeReceiptDigest(receipt) };
}

export function assertSchemaId(receipt: Record<string, unknown>): string | null {
  if (receipt.schema !== LIABILITY_RECEIPT_SCHEMA) {
    return `schema must be "${LIABILITY_RECEIPT_SCHEMA}"`;
  }
  return null;
}
