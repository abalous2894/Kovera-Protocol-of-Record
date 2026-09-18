/**
 * Wave 15 Track B — offline Rekor RFC 6962 inclusion proof verification.
 * No HTTP to Rekor or Aevesa — third parties verify bundled crypto artifacts locally.
 */

import { sha256Buffer } from '../core/sha256.js';

export const REKOR_INCLUSION_PROOF_SCHEMA = 'aevesa.witness.rekor-inclusion-proof/v1';
export const REKOR_INCLUSION_VERIFY_SCHEMA = 'aevesa.witness.rekor-inclusion-verify/v1';
export const REKOR_INCLUSION_PROOF_REQUIRED = 'REKOR_INCLUSION_PROOF_REQUIRED';
export const REKOR_INCLUSION_DIGEST_MISMATCH = 'REKOR_INCLUSION_DIGEST_MISMATCH';

const RFC6962_LEAF_PREFIX = 0x00;
const RFC6962_NODE_PREFIX = 0x01;
const HEX64 = /^[a-f0-9]{64}$/;

/**
 * @param {string} value
 * @param {string} label
 */
function decodeProofHash(value, label) {
  const trimmed = String(value || '').trim().toLowerCase().replace(/^0x/, '');
  if (!HEX64.test(trimmed)) {
    throw new Error(`${label} is not a 32-byte hex hash`);
  }
  return trimmed;
}

/**
 * RFC 6962 leaf hash: SHA-256(0x00 || body).
 * @param {Buffer | Uint8Array} bodyBytes
 */
export function rfc6962LeafHash(bodyBytes) {
  const body = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(bodyBytes);
  const preimage = Buffer.concat([Buffer.from([RFC6962_LEAF_PREFIX]), body]);
  return sha256Buffer(preimage);
}

/**
 * RFC 6962 interior node: SHA-256(0x01 || left || right).
 * @param {string} leftHex
 * @param {string} rightHex
 */
export function rfc6962NodeHash(leftHex, rightHex) {
  const left = Buffer.from(decodeProofHash(leftHex, 'left hash'), 'hex');
  const right = Buffer.from(decodeProofHash(rightHex, 'right hash'), 'hex');
  const preimage = Buffer.concat([Buffer.from([RFC6962_NODE_PREFIX]), left, right]);
  return sha256Buffer(preimage);
}

/**
 * Recompute Merkle tree root from an RFC 6962 inclusion proof (Rekor audit path).
 * @param {{ leafIndex: number; treeSize: number; leafHashHex: string; hashesHex: string[] }}
 */
export function computeRfc6962RootFromInclusionProof({ leafIndex, treeSize, leafHashHex, hashesHex }) {
  const errors = [];
  if (!Number.isInteger(treeSize) || treeSize <= 0) {
    return { ok: false, rootHex: null, errors: ['tree_size must be a positive integer'] };
  }
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) {
    return {
      ok: false,
      rootHex: null,
      errors: [`log_index ${leafIndex} is out of range for tree_size ${treeSize}`],
    };
  }

  let leafHash;
  try {
    leafHash = decodeProofHash(leafHashHex, 'leaf hash');
  } catch (error) {
    return {
      ok: false,
      rootHex: null,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }

  const auditPath = [];
  for (let i = 0; i < hashesHex.length; i += 1) {
    try {
      auditPath.push(decodeProofHash(hashesHex[i], `audit path hash[${i}]`));
    } catch (error) {
      return {
        ok: false,
        rootHex: null,
        errors: [error instanceof Error ? error.message : String(error)],
      };
    }
  }

  let nodeIndex = leafIndex;
  let lastIndex = treeSize - 1;
  let computed = leafHash;
  let consumed = 0;

  while (lastIndex > 0) {
    if (consumed >= auditPath.length) {
      errors.push(
        `audit path too short: needed more than ${auditPath.length} hashes for tree_size ${treeSize}`,
      );
      return { ok: false, rootHex: null, errors };
    }
    const sibling = auditPath[consumed];
    consumed += 1;

    if (nodeIndex % 2 === 1 || nodeIndex === lastIndex) {
      computed = rfc6962NodeHash(sibling, computed);
      while (nodeIndex % 2 === 0 && nodeIndex !== 0) {
        nodeIndex = Math.floor(nodeIndex / 2);
        lastIndex = Math.floor(lastIndex / 2);
      }
    } else {
      computed = rfc6962NodeHash(computed, sibling);
    }
    nodeIndex = Math.floor(nodeIndex / 2);
    lastIndex = Math.floor(lastIndex / 2);
  }

  if (consumed !== auditPath.length) {
    errors.push(
      `audit path too long: consumed ${consumed} of ${auditPath.length} hashes for tree_size ${treeSize}`,
    );
    return { ok: false, rootHex: null, errors };
  }

  return { ok: true, rootHex: computed, errors: [] };
}

/**
 * @param {string} entryBodyBase64
 */
export function computeRekorLeafHashFromBodyBase64(entryBodyBase64) {
  const bodyBytes = Buffer.from(String(entryBodyBase64 || ''), 'base64');
  return rfc6962LeafHash(bodyBytes);
}

/**
 * Canonical hashedrekord JSON body Aevesa submits to Rekor (matches backend POST).
 * @param {string} digestHex
 */
export function buildHashedRekordEntryBodyJson(digestHex) {
  const digest = String(digestHex || '').trim().toLowerCase();
  return JSON.stringify({
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: { data: { hash: { algorithm: 'sha256', value: digest } } },
  });
}

/**
 * @param {string} digestHex
 */
export function buildHashedRekordEntryBodyBase64(digestHex) {
  return Buffer.from(buildHashedRekordEntryBodyJson(digestHex), 'utf8').toString('base64');
}

/**
 * Extract committed digest from a Rekor log entry body (hashedrekord).
 * @param {Buffer | Uint8Array | string} bodyBytesOrBase64
 */
export function extractHashedRekordDigestFromEntryBody(bodyBytesOrBase64) {
  let bodyBytes;
  if (typeof bodyBytesOrBase64 === 'string') {
    const raw = String(bodyBytesOrBase64 || '').trim();
    bodyBytes = /^[A-Za-z0-9+/=]+$/.test(raw) && !raw.startsWith('{')
      ? Buffer.from(raw, 'base64')
      : Buffer.from(raw, 'utf8');
  } else {
    bodyBytes = Buffer.isBuffer(bodyBytesOrBase64)
      ? bodyBytesOrBase64
      : Buffer.from(bodyBytesOrBase64);
  }

  let parsed;
  try {
    parsed = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    return { ok: false, digest: null, errors: ['rekor entry body is not valid JSON'] };
  }

  const hashNode =
    parsed?.spec?.data?.hash ??
    parsed?.Spec?.Data?.Hash ??
    null;
  const algorithm = String(hashNode?.algorithm ?? hashNode?.Algorithm ?? 'sha256').toLowerCase();
  const value = String(hashNode?.value ?? hashNode?.Value ?? '').trim().toLowerCase();

  if (algorithm && algorithm !== 'sha256') {
    return { ok: false, digest: null, errors: [`rekor entry hash algorithm must be sha256, got ${algorithm}`] };
  }
  if (!HEX64.test(value)) {
    return { ok: false, digest: null, errors: ['rekor entry body missing spec.data.hash.value (64-char hex)'] };
  }

  return { ok: true, digest: value, errors: [] };
}

/**
 * Build a single-leaf Rekor inclusion proof document for tests (tree_size=1).
 * @param {string} digestHex
 */
export function buildSingleLeafRekorInclusionProofDocument(digestHex) {
  const entryBodyBase64 = buildHashedRekordEntryBodyBase64(digestHex);
  const leafHash = computeRekorLeafHashFromBodyBase64(entryBodyBase64);
  return {
    schema: REKOR_INCLUSION_PROOF_SCHEMA,
    log_index: 0,
    tree_size: 1,
    root_hash: leafHash,
    hashes: [],
    entry_body_base64: entryBodyBase64,
    log_id: 'rekor.sigstore.dev',
    checkpoint: `rekor.sigstore.dev\n1\n${leafHash}\n— MEQCIFixtureOnlyNotARealSignature`,
  };
}

/**
 * Parse Rekor signed checkpoint envelope — bind root + tree size without cosign verify (B-PR1).
 * @param {string} checkpoint
 */
export function parseRekorCheckpointEnvelope(checkpoint) {
  const lines = String(checkpoint || '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length < 4) {
    return { ok: false, logId: null, treeSize: null, rootHash: null, errors: ['checkpoint envelope too short'] };
  }

  const signatureLine = lines[lines.length - 1];
  if (!signatureLine.startsWith('—') && !signatureLine.startsWith('--')) {
    return { ok: false, logId: null, treeSize: null, rootHash: null, errors: ['checkpoint missing signature line'] };
  }

  const logId = lines[0];
  const treeSize = Number(lines[1]);
  const rootHashRaw = lines[2];

  if (!Number.isInteger(treeSize) || treeSize <= 0) {
    return { ok: false, logId, treeSize: null, rootHash: null, errors: ['checkpoint tree size invalid'] };
  }

  let rootHash;
  try {
    rootHash = decodeProofHash(rootHashRaw, 'checkpoint rootHash');
  } catch (error) {
    return {
      ok: false,
      logId,
      treeSize,
      rootHash: null,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }

  return { ok: true, logId, treeSize, rootHash, errors: [] };
}

/**
 * @param {unknown} proof
 * @param {{ expectedLogIndex?: number | null; expectedLogId?: string | null; expectedStatementDigest?: string | null }} [options]
 */
export function verifyRekorCryptoInclusionProof(proof, options = {}) {
  const result = {
    schema: REKOR_INCLUSION_VERIFY_SCHEMA,
    ok: false,
    checks: {
      schemaValid: false,
      fieldsPresent: false,
      leafHashResolved: false,
      entryBodyDigestBinding: null,
      rootRecompute: false,
      rootMatchesProof: false,
      logIndexConsistent: true,
      checkpointPresent: false,
      checkpointRootMatches: null,
      checkpointTreeSizeMatches: null,
    },
    computed_root: null,
    errors: [],
    codes: [],
    note: null,
  };

  if (!proof || typeof proof !== 'object') {
    result.errors.push('rekor inclusion proof missing');
    result.codes.push(REKOR_INCLUSION_PROOF_REQUIRED);
    return result;
  }

  const doc = /** @type {Record<string, unknown>} */ (proof);
  result.checks.schemaValid = doc.schema === REKOR_INCLUSION_PROOF_SCHEMA;
  if (!result.checks.schemaValid) {
    result.errors.push(`schema must be ${REKOR_INCLUSION_PROOF_SCHEMA}`);
  }

  const logIndex = Number(doc.log_index ?? doc.logIndex ?? -1);
  const treeSize = Number(doc.tree_size ?? doc.treeSize ?? -1);
  const rootHash = String(doc.root_hash ?? doc.rootHash ?? '').toLowerCase();
  const hashesRaw = doc.hashes ?? doc.audit_path ?? doc.auditPath ?? null;
  const hashes = Array.isArray(hashesRaw) ? hashesRaw.map((item) => String(item)) : null;

  result.checks.fieldsPresent =
    Number.isInteger(logIndex) &&
    logIndex >= 0 &&
    Number.isInteger(treeSize) &&
    treeSize > 0 &&
    HEX64.test(rootHash) &&
    Array.isArray(hashes);

  if (!result.checks.fieldsPresent) {
    result.errors.push('rekor inclusion proof missing log_index, tree_size, root_hash, or hashes');
    result.codes.push(REKOR_INCLUSION_PROOF_REQUIRED);
    return result;
  }

  const expectedStatementDigest = String(options.expectedStatementDigest || '')
    .trim()
    .toLowerCase();
  const requiresDigestBinding = HEX64.test(expectedStatementDigest);

  let leafHash = doc.leaf_hash ?? doc.leafHash ?? null;
  const entryBodyBase64 = doc.entry_body_base64 ?? doc.entryBodyBase64 ?? null;

  if (requiresDigestBinding && !entryBodyBase64) {
    result.errors.push(
      'entry_body_base64 required to bind Rekor inclusion proof to statement digest (leaf_hash alone is insufficient)',
    );
    result.codes.push(REKOR_INCLUSION_DIGEST_MISMATCH);
    return result;
  }

  if (!leafHash && entryBodyBase64) {
    try {
      leafHash = computeRekorLeafHashFromBodyBase64(String(entryBodyBase64));
      result.checks.leafHashResolved = true;
    } catch (error) {
      result.errors.push(`entry_body_base64 decode failed: ${error instanceof Error ? error.message : String(error)}`);
      return result;
    }
  } else if (leafHash) {
    try {
      leafHash = decodeProofHash(String(leafHash), 'leaf_hash');
      result.checks.leafHashResolved = true;
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
      return result;
    }
  } else {
    result.errors.push('leaf_hash or entry_body_base64 required to bind inclusion proof to entry body');
    result.codes.push(REKOR_INCLUSION_PROOF_REQUIRED);
    return result;
  }

  if (requiresDigestBinding && entryBodyBase64) {
    const extracted = extractHashedRekordDigestFromEntryBody(String(entryBodyBase64));
    if (!extracted.ok) {
      result.checks.entryBodyDigestBinding = false;
      result.errors.push(...extracted.errors);
      result.codes.push(REKOR_INCLUSION_DIGEST_MISMATCH);
      return result;
    }
    result.checks.entryBodyDigestBinding = extracted.digest === expectedStatementDigest;
    if (!result.checks.entryBodyDigestBinding) {
      result.errors.push(
        `rekor entry body digest ${extracted.digest} does not match expected statement digest ${expectedStatementDigest}`,
      );
      result.codes.push(REKOR_INCLUSION_DIGEST_MISMATCH);
      return result;
    }
  }

  if (options.expectedLogIndex != null && Number(options.expectedLogIndex) !== logIndex) {
    result.checks.logIndexConsistent = false;
    result.errors.push(
      `log_index ${logIndex} does not match expected metadata log_index ${options.expectedLogIndex}`,
    );
  }

  const recompute = computeRfc6962RootFromInclusionProof({
    leafIndex: logIndex,
    treeSize,
    leafHashHex: String(leafHash),
    hashesHex: hashes,
  });

  result.checks.rootRecompute = recompute.ok;
  if (!recompute.ok) {
    result.errors.push(...recompute.errors);
    return result;
  }

  result.computed_root = recompute.rootHex;
  result.checks.rootMatchesProof = recompute.rootHex === rootHash;
  if (!result.checks.rootMatchesProof) {
    result.errors.push(
      `root mismatch: recomputed ${recompute.rootHex} but proof asserts ${rootHash}`,
    );
    return result;
  }

  const checkpoint = doc.checkpoint ?? null;
  if (checkpoint) {
    result.checks.checkpointPresent = true;
    const parsed = parseRekorCheckpointEnvelope(String(checkpoint));
    if (!parsed.ok) {
      result.errors.push(...parsed.errors);
      return result;
    }
    if (options.expectedLogId && parsed.logId !== options.expectedLogId) {
      result.errors.push(`checkpoint log id ${parsed.logId} does not match expected ${options.expectedLogId}`);
      return result;
    }
    result.checks.checkpointTreeSizeMatches = parsed.treeSize === treeSize;
    result.checks.checkpointRootMatches = parsed.rootHash === rootHash;
    if (!result.checks.checkpointTreeSizeMatches) {
      result.errors.push(`checkpoint tree size ${parsed.treeSize} does not match proof tree_size ${treeSize}`);
      return result;
    }
    if (!result.checks.checkpointRootMatches) {
      result.errors.push(`checkpoint root ${parsed.rootHash} does not match proof root_hash ${rootHash}`);
      return result;
    }
  }

  result.ok =
    result.checks.schemaValid &&
    result.checks.fieldsPresent &&
    result.checks.leafHashResolved &&
    (result.checks.entryBodyDigestBinding === null || result.checks.entryBodyDigestBinding === true) &&
    result.checks.rootRecompute &&
    result.checks.rootMatchesProof &&
    result.checks.logIndexConsistent &&
    (result.checks.checkpointPresent
      ? result.checks.checkpointRootMatches === true && result.checks.checkpointTreeSizeMatches === true
      : true);

  result.note = result.ok
    ? checkpoint
      ? 'Rekor inclusion proof verified offline — RFC 6962 root + hashedrekord digest binding + checkpoint envelope (signature not verified)'
      : requiresDigestBinding
        ? 'Rekor inclusion proof verified offline — RFC 6962 root recompute + hashedrekord digest binding'
        : 'Rekor inclusion proof verified offline — RFC 6962 root recompute matches bundled root_hash'
    : null;

  return result;
}

export default {
  REKOR_INCLUSION_PROOF_SCHEMA,
  REKOR_INCLUSION_VERIFY_SCHEMA,
  REKOR_INCLUSION_PROOF_REQUIRED,
  REKOR_INCLUSION_DIGEST_MISMATCH,
  rfc6962LeafHash,
  rfc6962NodeHash,
  computeRfc6962RootFromInclusionProof,
  computeRekorLeafHashFromBodyBase64,
  buildHashedRekordEntryBodyJson,
  buildHashedRekordEntryBodyBase64,
  extractHashedRekordDigestFromEntryBody,
  buildSingleLeafRekorInclusionProofDocument,
  parseRekorCheckpointEnvelope,
  verifyRekorCryptoInclusionProof,
};
