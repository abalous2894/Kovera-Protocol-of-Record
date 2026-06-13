/**
 * Recompute aegis/1 entryHash from persisted row fields (offline verify).
 */

import { sha256Utf8 } from './sha256.js';
import { canonicalize } from './canonicalize.js';
import { resolveGovernanceBinding } from './governanceBinding.js';
import {
  AEGIS_LEDGER_PREIMAGE_SPEC,
  AEGIS_ENTRY_HASH_INPUT_KEYS,
  AEGIS_CONTEXT_LINKAGE_KEYS,
} from './aegisPreimageSpec.js';
import { verifyProofOfIntentForStoredRow } from './proofOfIntent.js';

/**
 * @param {Date | string} ts
 */
export function formatAegisLedgerTimestampIso(ts) {
  if (ts instanceof Date) {
    return ts.toISOString();
  }
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) {
    throw new Error('Invalid ledger timestamp');
  }
  return d.toISOString();
}

/**
 * @param {object} doc — Mongo AuditLog lean document or JSON export
 */
export function buildGovernanceBindingFromStoredDoc(doc) {
  const payload = doc?.payload && typeof doc.payload === 'object' ? doc.payload : {};
  const { forHash } = resolveGovernanceBinding({
    cost: doc?.cost,
    approverId: doc?.approverId,
    policyId: doc?.policyId,
    forensicSnapshot: doc?.forensicSnapshot,
    proofOfIntent: doc?.proofOfIntent,
    intentContext: doc?.intentContext ?? payload?.intent_context ?? payload?.intentContext,
    normalizedPayload: payload,
  });
  return forHash;
}

/**
 * @param {object} doc
 */
export function buildContextLinkageFromStoredDoc(doc) {
  const payload = doc?.payload && typeof doc.payload === 'object' ? doc.payload : {};
  return {
    agentId: String(doc.agentId),
    eventType: String(doc.eventType),
    severity: String(doc.severity ?? 'INFO'),
    payload,
    timestamp: formatAegisLedgerTimestampIso(doc.timestamp),
  };
}

/**
 * @param {object} doc
 */
export function buildEntryHashPreimageFromStoredDoc(doc) {
  const payload = doc?.payload && typeof doc.payload === 'object' ? doc.payload : {};
  const prebuiltBinding =
    doc?.governanceBinding && typeof doc.governanceBinding === 'object' ? doc.governanceBinding : null;
  return {
    agentId: String(doc.agentId),
    eventType: String(doc.eventType),
    severity: String(doc.severity ?? 'INFO'),
    payload,
    timestamp: formatAegisLedgerTimestampIso(doc.timestamp),
    prevHash: doc?.prevHash != null ? String(doc.prevHash) : 'GENESIS',
    contextHash: doc?.contextHash != null ? String(doc.contextHash) : null,
    governanceBinding: prebuiltBinding ?? buildGovernanceBindingFromStoredDoc(doc),
  };
}

/**
 * @param {ReturnType<typeof buildEntryHashPreimageFromStoredDoc>} preimage
 */
export function serializeEntryHashInput(preimage) {
  const ordered = {};
  for (const key of AEGIS_ENTRY_HASH_INPUT_KEYS) {
    ordered[key] = preimage[key];
  }
  return JSON.stringify(ordered);
}

/**
 * @param {object} linkage
 */
export function serializeContextLinkage(linkage) {
  const ordered = {};
  for (const key of AEGIS_CONTEXT_LINKAGE_KEYS) {
    ordered[key] = linkage[key];
  }
  return JSON.stringify(ordered);
}

/**
 * @param {ReturnType<typeof buildEntryHashPreimageFromStoredDoc>} preimage
 */
export function computeEntryHashFromPreimage(preimage) {
  return sha256Utf8(serializeEntryHashInput(preimage));
}

/**
 * @param {string} prevContextHash
 * @param {object} linkage
 */
export function computeContextHashFromLinkage(prevContextHash, linkage) {
  const prev = prevContextHash != null && String(prevContextHash).trim() ? String(prevContextHash) : 'GENESIS';
  const linkageDigest = sha256Utf8(serializeContextLinkage(linkage));
  return sha256Utf8(`${prev}:${linkageDigest}`);
}

export function sealAegisLedgerRow({
  agentId,
  eventType,
  severity,
  payload,
  timestamp,
  prevHash,
  prevContextHash,
  governanceBinding,
}) {
  const tsIso = formatAegisLedgerTimestampIso(timestamp);
  const linkage = {
    agentId: String(agentId),
    eventType: String(eventType),
    severity: String(severity ?? 'INFO'),
    payload,
    timestamp: tsIso,
  };
  const contextHash = computeContextHashFromLinkage(prevContextHash, linkage);
  const preimage = {
    agentId: String(agentId),
    eventType: String(eventType),
    severity: String(severity ?? 'INFO'),
    payload,
    timestamp: tsIso,
    prevHash: prevHash != null ? String(prevHash) : 'GENESIS',
    contextHash,
    governanceBinding,
  };
  return {
    contextHash,
    entryHash: computeEntryHashFromPreimage(preimage),
    preimage,
    hashInput: serializeEntryHashInput(preimage),
  };
}

/**
 * @param {object} doc — ledger row JSON
 * @param {{ prevContextHash?: string | null, verifyProofOfIntent?: boolean }} [opts]
 */
export function verifyLedgerEntryPreimage(doc, opts = {}) {
  const storedHash = String(doc?.entryHash || '')
    .trim()
    .toLowerCase();
  const preimage = buildEntryHashPreimageFromStoredDoc(doc);
  const recomputedEntryHash = computeEntryHashFromPreimage(preimage);
  const entryHashMatch = storedHash === recomputedEntryHash;

  const linkage = buildContextLinkageFromStoredDoc(doc);
  let contextHashRecomputed = null;
  let contextHashMatch = null;
  let prevContextHashUsed = null;

  if (doc?.contextHash != null) {
    prevContextHashUsed =
      opts.prevContextHash != null
        ? String(opts.prevContextHash)
        : doc.prevHash === 'GENESIS' || !doc.prevHash
          ? 'GENESIS'
          : null;
    if (prevContextHashUsed == null) {
      return {
        spec: AEGIS_LEDGER_PREIMAGE_SPEC,
        ok: false,
        error: 'CONTEXT_CHAIN_REQUIRES_PREV_CONTEXT_HASH',
        detail: 'contextHash set — pass --prev-context-hash or _verify.prevContextHash',
        storedEntryHash: storedHash,
        recomputedEntryHash,
        entryHashMatch,
      };
    }
    contextHashRecomputed = computeContextHashFromLinkage(prevContextHashUsed, linkage);
    contextHashMatch = String(doc.contextHash).toLowerCase() === contextHashRecomputed;
  }

  /** @type {Array<{ id: string, pass: boolean, detail: string }>} */
  const layers = [
    {
      id: 'entry_hash_recompute',
      pass: entryHashMatch,
      detail: entryHashMatch
        ? 'entryHash matches aegis/1 preimage'
        : `mismatch stored=${storedHash} recomputed=${recomputedEntryHash}`,
    },
  ];

  if (doc?.contextHash != null) {
    layers.push({
      id: 'context_hash_recompute',
      pass: contextHashMatch === true,
      detail:
        contextHashMatch === true
          ? 'contextHash matches aegis/1 context linkage'
          : `mismatch stored=${doc.contextHash} recomputed=${contextHashRecomputed}`,
    });
  }

  let proofOfIntentResult = null;
  if (opts.verifyProofOfIntent !== false) {
    proofOfIntentResult = verifyProofOfIntentForStoredRow(doc);
    if (proofOfIntentResult.applicable) {
      layers.push({
        id: 'proof_of_intent_recompute',
        pass: proofOfIntentResult.ok === true,
        detail: proofOfIntentResult.detail || 'proof-of-intent check',
      });
    }
  }

  const result = {
    spec: AEGIS_LEDGER_PREIMAGE_SPEC,
    ok: layers.every((l) => l.pass),
    storedEntryHash: storedHash,
    recomputedEntryHash,
    entryHashMatch,
    preimageForAudit: {
      ...preimage,
      payload: canonicalize(preimage.payload),
      governanceBinding: canonicalize(preimage.governanceBinding),
    },
    serializedEntryHashInput: serializeEntryHashInput(preimage),
    contextLinkage: linkage,
    contextHashRecomputed,
    contextHashMatch,
    prevContextHashUsed,
    proofOfIntent: proofOfIntentResult,
    layers,
  };

  return result;
}
