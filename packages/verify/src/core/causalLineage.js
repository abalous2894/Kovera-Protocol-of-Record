/**
 * KVR-301 — Swarm / multi-agent causal lineage for liability-receipt/v1 digest binding.
 * Aligns with aegis/1 proofOfIntent causalBinding (parentEntryHash) but uses receipt snake_case.
 */

const HEX64 = /^[a-f0-9]{64}$/;

/**
 * @param {string | null | undefined} value
 */
function normalizeHex64(value) {
  if (value == null || !String(value).trim()) return null;
  const lower = String(value).trim().toLowerCase();
  return HEX64.test(lower) ? lower : null;
}

/**
 * @param {string | null | undefined} value
 * @param {number} maxLen
 */
function normalizeSessionRef(value, maxLen = 256) {
  if (value == null || !String(value).trim()) return null;
  const s = String(value).trim();
  if (!s || s.length > maxLen) return null;
  return s;
}

/**
 * Extract causal lineage from a ledger payload or mint input (camelCase or snake_case).
 * @param {object | null | undefined} payload
 * @returns {{ parent_entry_hash: string, parent_session_id?: string, root_session_id?: string } | null}
 */
export function extractCausalLineageFromPayload(payload) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const parentEntryHash = normalizeHex64(p.parentEntryHash ?? p.parent_entry_hash);
  if (!parentEntryHash) return null;

  /** @type {{ parent_entry_hash: string, parent_session_id?: string, root_session_id?: string }} */
  const lineage = { parent_entry_hash: parentEntryHash };

  const parentSessionId = normalizeSessionRef(p.parentSessionId ?? p.parent_session_id);
  if (parentSessionId) lineage.parent_session_id = parentSessionId;

  const rootSessionId = normalizeSessionRef(p.rootSessionId ?? p.root_session_id);
  if (rootSessionId) lineage.root_session_id = rootSessionId;

  return lineage;
}

/**
 * Canonical form bound into receipt_digest (stable key order, lowercase parent hash).
 * @param {object | null | undefined} lineage
 */
export function canonicalizeCausalLineageForDigest(lineage) {
  if (!lineage || typeof lineage !== 'object') return null;
  const parentEntryHash = normalizeHex64(lineage.parent_entry_hash ?? lineage.parentEntryHash);
  if (!parentEntryHash) return null;

  /** @type {{ parent_entry_hash: string, parent_session_id?: string, root_session_id?: string }} */
  const out = { parent_entry_hash: parentEntryHash };

  const parentSessionId = normalizeSessionRef(lineage.parent_session_id ?? lineage.parentSessionId);
  if (parentSessionId) out.parent_session_id = parentSessionId;

  const rootSessionId = normalizeSessionRef(lineage.root_session_id ?? lineage.rootSessionId);
  if (rootSessionId) out.root_session_id = rootSessionId;

  return out;
}

/**
 * Map receipt causal_lineage to proofOfIntent causalBinding shape for cross-checks.
 * @param {object | null | undefined} lineage
 */
export function causalLineageToProofBinding(lineage) {
  const canon = canonicalizeCausalLineageForDigest(lineage);
  if (!canon) return null;
  return {
    parentEntryHash: canon.parent_entry_hash,
    ...(canon.parent_session_id ? { parentSessionId: canon.parent_session_id } : {}),
    ...(canon.root_session_id ? { rootSessionId: canon.root_session_id } : {}),
  };
}
