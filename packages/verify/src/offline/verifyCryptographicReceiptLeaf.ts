import { readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import {
  CRYPTOGRAPHIC_RECEIPT_LEAF_SCHEMA,
  computeCryptographicReceiptLeafDigest,
  type CryptographicReceiptLeafInput,
} from '../core/cryptographicReceiptLeaf.js';
import { assertNoForbiddenKeys, normalizeUnicodeNfkc } from '../core/jcsSafeObject.js';
import { isRecord } from '../core/isRecord.js';

const HEX64 = /^[a-f0-9]{64}$/i;

export interface LeafExtraction {
  ok: true;
  sourcePath: string;
  leaf: CryptographicReceiptLeafInput;
  storedDigest: string;
  fieldPath: string;
}

export interface LeafExtractionError {
  ok: false;
  sourcePath: string;
  code:
    | 'MISSING_FILE'
    | 'INVALID_JSON'
    | 'MISSING_LEAF'
    | 'MISSING_DIGEST'
    | 'MISSING_LEAF_FIELDS'
    | 'MISSING_VALIDATION_KEYS';
  message: string;
  fieldPath?: string;
}

export interface LeafVerifySuccess {
  ok: true;
  sourcePath: string;
  storedDigest: string;
  recomputedDigest: string;
  fieldPath: string;
  leaf: CryptographicReceiptLeafInput;
}

export interface LeafVerifyFailure {
  ok: false;
  sourcePath: string;
  code: 'DIGEST_MISMATCH' | 'MISSING_VALIDATION_KEYS' | LeafExtractionError['code'];
  message: string;
  fieldPath?: string;
  storedDigest?: string;
  recomputedDigest?: string;
  mutatedFields?: string[];
}

export type LeafVerifyResult = LeafVerifySuccess | LeafVerifyFailure;

export interface ChainVerifySuccess {
  ok: true;
  count: number;
  digests: string[];
}

export interface ChainVerifyFailure {
  ok: false;
  code: 'CHAIN_BROKEN' | 'CHAIN_DIGEST_FAILED';
  message: string;
  index: number;
  sourcePath: string;
  expectedPrevHash?: string;
  actualPrevHash?: string;
  leafFailure?: LeafVerifyFailure;
}

export type ChainVerifyResult = ChainVerifySuccess | ChainVerifyFailure;

function normalizeHex64(value: unknown): string | null {
  const s = String(value ?? '').trim().toLowerCase();
  return HEX64.test(s) ? s : null;
}

function pickString(obj: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = obj[k];
    if (v != null && String(v).trim()) return String(v).trim();
  }
  return '';
}

function pickInt(obj: Record<string, unknown>, ...keys: string[]): number | null {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'number' && Number.isInteger(v) && v >= 0) return v;
  }
  return null;
}

/**
 * Map liability-receipt/v1 + audit-log export shapes into a cryptographic leaf.
 */
function leafFromLiabilityReceipt(doc: Record<string, unknown>): {
  leaf: CryptographicReceiptLeafInput;
  storedDigest: string;
  fieldPath: string;
} | null {
  const embedded = doc.receiptLeaf;
  if (isRecord(embedded)) {
    const digest =
      normalizeHex64(embedded.receiptLeafDigest) ??
      normalizeHex64(doc.receiptLeafDigest) ??
      normalizeHex64(doc.integrity && isRecord(doc.integrity) ? doc.integrity.receipt_leaf_digest : null);
    if (digest && isLeafInputShape(embedded)) {
      return {
        leaf: normalizeLeafInput(embedded),
        storedDigest: digest,
        fieldPath: 'receiptLeaf',
      };
    }
  }

  const payload = doc.payload;
  if (isRecord(payload) && isRecord(payload.receiptLeaf)) {
    const rl = payload.receiptLeaf;
    const digest =
      normalizeHex64(rl.receiptLeafDigest) ??
      normalizeHex64(payload.receiptLeafDigest) ??
      normalizeHex64(doc.receiptLeafDigest);
    if (digest && isLeafInputShape(rl)) {
      return {
        leaf: normalizeLeafInput(rl),
        storedDigest: digest,
        fieldPath: 'payload.receiptLeaf',
      };
    }
  }

  const proofRaw = doc.proof;
  const proof = isRecord(proofRaw) ? proofRaw : null;
  const anchor =
    proof && isRecord(proof.primary_anchor) ? proof.primary_anchor : {};
  if (proof && isRecord(proof.cryptographic_leaf)) {
    const cl = proof.cryptographic_leaf;
    const digest = normalizeHex64(cl.receiptLeafDigest) ?? normalizeHex64(proof.receipt_leaf_digest);
    if (digest && isLeafInputShape(cl)) {
      return {
        leaf: normalizeLeafInput(cl),
        storedDigest: digest,
        fieldPath: 'proof.cryptographic_leaf',
      };
    }
  }

  const integrity = doc.integrity;
  const storedDigest =
    normalizeHex64(doc.receiptLeafDigest) ??
    normalizeHex64(integrity && isRecord(integrity) ? integrity.receipt_leaf_digest : null);

  if (!storedDigest) return null;

  const identity = isRecord(doc.identity) ? doc.identity : {};
  const primary = isRecord(identity.primary_actor) ? identity.primary_actor : {};
  const session = isRecord(doc.session) ? doc.session : {};
  const sideEffects = isRecord(doc.side_effects) ? doc.side_effects : {};
  const action = isRecord(sideEffects.action) ? sideEffects.action : {};
  const policy = isRecord(doc.policy) ? doc.policy : {};

  const leaf: CryptographicReceiptLeafInput = {
    prevEntryHash:
      pickString(doc, 'prevEntryHash', 'prevHash') ||
      pickString(anchor, 'prev_entry_hash', 'prevEntryHash', 'prev_hash') ||
      'GENESIS',
    agentId:
      pickString(doc, 'agentId') ||
      pickString(primary, 'agent_id', 'agentId') ||
      pickString(identity, 'agent_id'),
    sessionId:
      pickString(doc, 'sessionId') ||
      pickString(session, 'session_id', 'sessionId') ||
      pickString(doc, 'correlation_id'),
    causalParent:
      pickString(doc, 'causalParent', 'toolCallId', 'causal_parent') ||
      (proof ? pickString(proof, 'causal_parent', 'tool_call_id') : '') ||
      pickString(session, 'correlation_id'),
    toolName:
      pickString(doc, 'toolName') ||
      pickString(action, 'tool_name', 'toolName') ||
      pickString(sideEffects, 'tool_name'),
    paramsHash:
      normalizeHex64(doc.paramsHash) ??
      normalizeHex64(doc.params_hash) ??
      normalizeHex64(action.params_hash) ??
      normalizeHex64(sideEffects.params_hash) ??
      '0'.repeat(64),
    mandateVersionHash:
      normalizeHex64(doc.mandateVersionHash) ??
      normalizeHex64(doc.mandate_version_hash) ??
      normalizeHex64(policy.policy_version_hash) ??
      '0'.repeat(64),
    wallTime:
      pickString(doc, 'wallTime', 'wall_time') ||
      pickString(doc, 'issued_at') ||
      pickString(anchor, 'timestamp') ||
      pickString(doc, 'timestamp'),
    logicalSeq:
      pickInt(doc, 'logicalSeq', 'logical_seq') ??
      pickInt(anchor, 'logical_seq', 'logicalSeq') ??
      0,
  };

  if (!leaf.agentId || !leaf.sessionId || !leaf.causalParent || !leaf.toolName || !leaf.wallTime) {
    return null;
  }

  return { leaf, storedDigest, fieldPath: 'integrity.receipt_leaf_digest (synthesized from receipt pillars)' };
}

function isLeafInputShape(obj: Record<string, unknown>): boolean {
  return (
    pickString(obj, 'agentId', 'agent_id') !== '' &&
    pickString(obj, 'sessionId', 'session_id') !== '' &&
    pickString(obj, 'causalParent', 'causal_parent', 'toolCallId') !== '' &&
    pickString(obj, 'toolName', 'tool_name') !== ''
  );
}

function normalizeLeafInput(obj: Record<string, unknown>): CryptographicReceiptLeafInput {
  assertNoForbiddenKeys(obj);
  return {
    prevEntryHash: pickString(obj, 'prevEntryHash', 'prev_entry_hash', 'prevHash') || 'GENESIS',
    agentId: normalizeUnicodeNfkc(pickString(obj, 'agentId', 'agent_id')),
    sessionId: normalizeUnicodeNfkc(pickString(obj, 'sessionId', 'session_id')),
    causalParent: normalizeUnicodeNfkc(pickString(obj, 'causalParent', 'causal_parent', 'toolCallId')),
    toolName: normalizeUnicodeNfkc(pickString(obj, 'toolName', 'tool_name')),
    paramsHash:
      normalizeHex64(obj.paramsHash) ??
      normalizeHex64(obj.params_hash) ??
      '0'.repeat(64),
    mandateVersionHash:
      normalizeHex64(obj.mandateVersionHash) ??
      normalizeHex64(obj.mandate_version_hash) ??
      '0'.repeat(64),
    wallTime: pickString(obj, 'wallTime', 'wall_time', 'timestamp', 'issued_at'),
    logicalSeq: pickInt(obj, 'logicalSeq', 'logical_seq') ?? 0,
  };
}

export function extractCryptographicLeafFromDocument(
  doc: unknown,
  sourcePath = '<memory>',
): LeafExtraction | LeafExtractionError {
  if (!isRecord(doc)) {
    return {
      ok: false,
      sourcePath,
      code: 'MISSING_LEAF',
      message: 'Receipt root must be a JSON object',
    };
  }

  try {
    assertNoForbiddenKeys(doc);
  } catch (e) {
    return {
      ok: false,
      sourcePath,
      code: 'MISSING_VALIDATION_KEYS',
      message: e instanceof Error ? e.message : String(e),
    };
  }

  if (doc.schema === CRYPTOGRAPHIC_RECEIPT_LEAF_SCHEMA) {
    const digest = normalizeHex64(doc.receiptLeafDigest);
    if (!digest) {
      return {
        ok: false,
        sourcePath,
        code: 'MISSING_DIGEST',
        message: 'Standalone cryptographic receipt leaf is missing receiptLeafDigest',
        fieldPath: 'receiptLeafDigest',
      };
    }
    return {
      ok: true,
      sourcePath,
      leaf: normalizeLeafInput(doc),
      storedDigest: digest,
      fieldPath: 'receiptLeafDigest',
    };
  }

  const mapped = leafFromLiabilityReceipt(doc);
  if (mapped) {
    return { ok: true, sourcePath, ...mapped };
  }

  return {
    ok: false,
    sourcePath,
    code: 'MISSING_VALIDATION_KEYS',
    message:
      'No cryptographic receipt leaf found. Expected receiptLeaf, payload.receiptLeaf, proof.cryptographic_leaf, or integrity.receipt_leaf_digest with bound pillar fields.',
  };
}

export function loadReceiptJson(filePath: string): { ok: true; doc: unknown } | { ok: false; error: LeafExtractionError } {
  const abs = resolve(filePath);
  let raw: string;
  try {
    raw = readFileSync(abs, 'utf8');
  } catch {
    return {
      ok: false,
      error: {
        ok: false,
        sourcePath: abs,
        code: 'MISSING_FILE',
        message: `Receipt file not found: ${abs}`,
      },
    };
  }
  try {
    return { ok: true, doc: JSON.parse(raw) as unknown };
  } catch (e) {
    return {
      ok: false,
      error: {
        ok: false,
        sourcePath: abs,
        code: 'INVALID_JSON',
        message: `Invalid JSON in receipt file: ${e instanceof Error ? e.message : String(e)}`,
      },
    };
  }
}

export function verifyCryptographicReceiptLeafDocument(
  doc: unknown,
  sourcePath = '<memory>',
): LeafVerifyResult {
  const extracted = extractCryptographicLeafFromDocument(doc, sourcePath);
  if (!extracted.ok) {
    return {
      ok: false,
      sourcePath: extracted.sourcePath,
      code: extracted.code,
      message: extracted.message,
      fieldPath: extracted.fieldPath,
    };
  }

  let recomputedDigest: string;
  try {
    recomputedDigest = computeCryptographicReceiptLeafDigest(extracted.leaf);
  } catch (e) {
    return {
      ok: false,
      sourcePath: extracted.sourcePath,
      code: 'MISSING_VALIDATION_KEYS',
      message: e instanceof Error ? e.message : String(e),
      fieldPath: extracted.fieldPath,
    };
  }

  if (recomputedDigest !== extracted.storedDigest) {
    const mutatedFields = diffLeafFields(extracted.leaf, recomputedDigest, extracted.storedDigest);
    return {
      ok: false,
      sourcePath: extracted.sourcePath,
      code: 'DIGEST_MISMATCH',
      message: `Cryptographic leaf digest mismatch — payload was mutated after sealing (field binding: ${extracted.fieldPath})`,
      fieldPath: extracted.fieldPath,
      storedDigest: extracted.storedDigest,
      recomputedDigest,
      mutatedFields,
    };
  }

  return {
    ok: true,
    sourcePath: extracted.sourcePath,
    storedDigest: extracted.storedDigest,
    recomputedDigest,
    fieldPath: extracted.fieldPath,
    leaf: extracted.leaf,
  };
}

function diffLeafFields(
  leaf: CryptographicReceiptLeafInput,
  _recomputed: string,
  _stored: string,
): string[] {
  const hints: string[] = [];
  for (const [key, value] of Object.entries(leaf)) {
    if (value == null || value === '') hints.push(String(key));
  }
  if (hints.length === 0) {
    hints.push(
      'prevEntryHash',
      'agentId',
      'sessionId',
      'causalParent',
      'toolName',
      'paramsHash',
      'mandateVersionHash',
      'wallTime',
      'logicalSeq',
    );
  }
  return hints;
}

export function resolveChainPaths(chainArg: string, cwd = process.cwd()): string[] {
  const trimmed = chainArg.trim();
  if (!trimmed) return [];

  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!Array.isArray(parsed)) throw new Error('--chain JSON must be an array of file paths');
    return parsed.map((p) => resolve(cwd, String(p)));
  }

  if (trimmed.includes(',')) {
    return trimmed.split(',').map((p) => resolve(cwd, p.trim())).filter(Boolean);
  }

  const abs = resolve(cwd, trimmed);
  const st = statSync(abs);
  if (st.isDirectory()) {
    return readdirSync(abs)
      .filter((name) => extname(name).toLowerCase() === '.json')
      .map((name) => join(abs, name))
      .sort((a, b) => a.localeCompare(b));
  }
  return [abs];
}

export function verifyCryptographicReceiptChain(filePaths: string[]): ChainVerifyResult {
  if (!filePaths.length) {
    return { ok: true, count: 0, digests: [] };
  }

  type LoadedEntry = {
    path: string;
    doc: unknown;
    logicalSeq: number;
  };

  const loadedEntries: LoadedEntry[] = [];
  for (const path of filePaths) {
    const loaded = loadReceiptJson(path);
    if (!loaded.ok) {
      return {
        ok: false,
        code: 'CHAIN_DIGEST_FAILED',
        message: loaded.error.message,
        index: loadedEntries.length,
        sourcePath: path,
        leafFailure: {
          ok: false,
          sourcePath: path,
          code: loaded.error.code,
          message: loaded.error.message,
        },
      };
    }
    const extracted = extractCryptographicLeafFromDocument(loaded.doc, path);
    const logicalSeq =
      extracted.ok && typeof extracted.leaf.logicalSeq === 'number'
        ? extracted.leaf.logicalSeq
        : loadedEntries.length;
    loadedEntries.push({ path, doc: loaded.doc, logicalSeq });
  }

  loadedEntries.sort((a, b) => a.logicalSeq - b.logicalSeq || a.path.localeCompare(b.path));

  const digests: string[] = [];
  let previousDigest: string | null = null;

  for (let i = 0; i < loadedEntries.length; i++) {
    const { path, doc } = loadedEntries[i];
    const verified = verifyCryptographicReceiptLeafDocument(doc, path);
    if (!verified.ok) {
      return {
        ok: false,
        code: 'CHAIN_DIGEST_FAILED',
        message: verified.message,
        index: i,
        sourcePath: path,
        leafFailure: verified,
      };
    }

    const expectedPrev =
      i === 0 ? 'GENESIS' : previousDigest ?? 'GENESIS';
    const actualPrev = verified.leaf.prevEntryHash.trim();
    const normalizedActual =
      actualPrev.toUpperCase() === 'GENESIS' ? 'GENESIS' : actualPrev.toLowerCase();
    const normalizedExpected =
      expectedPrev.toUpperCase() === 'GENESIS' ? 'GENESIS' : expectedPrev.toLowerCase();

    if (normalizedActual !== normalizedExpected) {
      return {
        ok: false,
        code: 'CHAIN_BROKEN',
        message: `Sequential chain broken at index ${i}: prevEntryHash does not match prior receipt digest`,
        index: i,
        sourcePath: path,
        expectedPrevHash: normalizedExpected,
        actualPrevHash: normalizedActual,
      };
    }

    digests.push(verified.recomputedDigest);
    previousDigest = verified.recomputedDigest;
  }

  return { ok: true, count: loadedEntries.length, digests };
}
