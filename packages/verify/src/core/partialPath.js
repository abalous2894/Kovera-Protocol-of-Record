/**
 * Aevesa Proof Moat Phase 3 — partial_path offline verify for liability-receipt/v1.
 */

import { createHash } from 'node:crypto';

export const PARTIAL_PATH_SCHEMA = 'aevesa.partial-path/v1';

/**
 * @param {unknown} partialPath
 * @returns {{ ok: boolean, code: string, expected?: string, got?: string }}
 */
export function verifyPartialPathCommitment(partialPath) {
  if (!partialPath || typeof partialPath !== 'object' || Array.isArray(partialPath)) {
    return { ok: false, code: 'INVALID_PARTIAL_PATH' };
  }
  const pp = /** @type {Record<string, unknown>} */ (partialPath);
  if (pp.schema !== PARTIAL_PATH_SCHEMA) {
    return { ok: false, code: 'INVALID_PARTIAL_PATH_SCHEMA' };
  }
  const stored = String(pp.partial_path_hash || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(stored)) {
    return { ok: false, code: 'MISSING_PARTIAL_PATH_HASH' };
  }
  const { partial_path_hash, ...rest } = pp;
  const expected = createHash('sha256').update(JSON.stringify(rest), 'utf8').digest('hex');
  if (expected !== stored) {
    return { ok: false, code: 'PARTIAL_PATH_HASH_MISMATCH', expected, got: stored };
  }
  return { ok: true, code: 'PARTIAL_PATH_VERIFIED' };
}

/**
 * @param {unknown} raw
 * @returns {Record<string, unknown> | null}
 */
export function canonicalizePartialPathForDigest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const src = /** @type {Record<string, unknown>} */ (raw);
  const hash = String(src.partial_path_hash || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) return null;
  return {
    schema: PARTIAL_PATH_SCHEMA,
    session_id: src.session_id ?? null,
    proposed_action: src.proposed_action ?? null,
    step_index: src.step_index ?? null,
    partial_path_hash: hash,
  };
}

export default { PARTIAL_PATH_SCHEMA, verifyPartialPathCommitment, canonicalizePartialPathForDigest };
