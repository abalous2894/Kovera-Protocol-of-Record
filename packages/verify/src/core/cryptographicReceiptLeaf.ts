import { createHash } from 'node:crypto';
import { canonicalizeJcs } from './jcs.js';
import { assertNoForbiddenKeys, normalizeUnicodeNfkc, toNullPrototypeRecord } from './jcsSafeObject.js';

export const CRYPTOGRAPHIC_RECEIPT_LEAF_SCHEMA = 'kovera/cryptographic-receipt-leaf/v1';

/** Normative leaf fields bound into the Merkle-DAG liability receipt. */
export const CRYPTOGRAPHIC_RECEIPT_LEAF_KEYS = [
  'schema',
  'prevEntryHash',
  'agentId',
  'sessionId',
  'causalParent',
  'toolName',
  'paramsHash',
  'mandateVersionHash',
  'wallTime',
  'logicalSeq',
] as const;

export type CryptographicReceiptLeafKey = (typeof CRYPTOGRAPHIC_RECEIPT_LEAF_KEYS)[number];

export interface CryptographicReceiptLeafInput {
  prevEntryHash: string;
  agentId: string;
  sessionId: string;
  /** Tool-call ID (causal parent in the execution DAG). */
  causalParent: string;
  toolName: string;
  /** SHA-256 hex of canonical tool parameters. */
  paramsHash: string;
  /** SHA-256 hex of active mandate / policy pack version. */
  mandateVersionHash: string;
  /** ISO-8601 wall clock at execution boundary. */
  wallTime: string;
  /** Monotonic logical sequence within session/agent. */
  logicalSeq: number;
}

export interface CryptographicReceiptLeaf extends CryptographicReceiptLeafInput {
  schema: typeof CRYPTOGRAPHIC_RECEIPT_LEAF_SCHEMA;
  /** SHA-256 hex of JCS-canonical leaf (self-reference excluded from preimage). */
  receiptLeafDigest?: string;
}

const HEX64 = /^[a-f0-9]{64}$/i;
const GENESIS = 'GENESIS';

function assertHex64OrGenesis(field: string, value: string): void {
  const v = String(value ?? '').trim();
  if (v === GENESIS || HEX64.test(v)) return;
  throw new TypeError(`${field} must be GENESIS or 64-char hex`);
}

/**
 * Build the structural receipt leaf (digest computed separately).
 */
export function buildCryptographicReceiptLeaf(
  input: CryptographicReceiptLeafInput,
): CryptographicReceiptLeaf {
  assertHex64OrGenesis('prevEntryHash', input.prevEntryHash);
  assertHex64OrGenesis('paramsHash', input.paramsHash);
  assertHex64OrGenesis('mandateVersionHash', input.mandateVersionHash);
  if (!Number.isInteger(input.logicalSeq) || input.logicalSeq < 0) {
    throw new TypeError('logicalSeq must be a non-negative integer');
  }
  if (!input.agentId?.trim()) throw new TypeError('agentId is required');
  if (!input.sessionId?.trim()) throw new TypeError('sessionId is required');
  if (!input.causalParent?.trim()) throw new TypeError('causalParent is required');
  if (!input.toolName?.trim()) throw new TypeError('toolName is required');
  if (!input.wallTime?.trim()) throw new TypeError('wallTime is required');

  assertNoForbiddenKeys(input);

  return {
    schema: CRYPTOGRAPHIC_RECEIPT_LEAF_SCHEMA,
    prevEntryHash: input.prevEntryHash.trim(),
    agentId: normalizeUnicodeNfkc(input.agentId),
    sessionId: normalizeUnicodeNfkc(input.sessionId),
    causalParent: normalizeUnicodeNfkc(input.causalParent),
    toolName: normalizeUnicodeNfkc(input.toolName),
    paramsHash: input.paramsHash.trim().toLowerCase(),
    mandateVersionHash: input.mandateVersionHash.trim().toLowerCase(),
    wallTime: input.wallTime.trim(),
    logicalSeq: input.logicalSeq,
  };
}

/**
 * JCS preimage for digest — explicit key order preserved via sorted JCS object keys.
 */
export function cryptographicReceiptLeafPreimage(
  leaf: CryptographicReceiptLeaf | CryptographicReceiptLeafInput,
): Record<string, unknown> {
  const built = buildCryptographicReceiptLeaf(leaf);
  const out = Object.create(null) as Record<string, unknown>;
  for (const key of CRYPTOGRAPHIC_RECEIPT_LEAF_KEYS) {
    out[key] = built[key as CryptographicReceiptLeafKey];
  }
  return toNullPrototypeRecord(out);
}

/**
 * SHA-256(JCS(leaf)) — offline-verifiable by third-party CLIs.
 */
export function computeCryptographicReceiptLeafDigest(
  input: CryptographicReceiptLeafInput,
): string {
  const preimage = cryptographicReceiptLeafPreimage(input);
  return createHash('sha256').update(canonicalizeJcs(preimage), 'utf8').digest('hex');
}

/**
 * Attach receiptLeafDigest to leaf document.
 */
export function sealCryptographicReceiptLeaf(
  input: CryptographicReceiptLeafInput,
): CryptographicReceiptLeaf {
  const leaf = buildCryptographicReceiptLeaf(input);
  const receiptLeafDigest = computeCryptographicReceiptLeafDigest(leaf);
  return { ...leaf, receiptLeafDigest };
}
