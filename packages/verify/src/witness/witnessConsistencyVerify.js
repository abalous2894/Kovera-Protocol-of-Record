/**
 * Track P12 — offline verification for witness log consistency proofs.
 */

import { sha256Utf8 } from '../core/sha256.js';

export const WITNESS_CONSISTENCY_PROOF_SCHEMA = 'aevesa.witness.consistency-proof/v1';

const HEX64 = /^[a-f0-9]{64}$/;

/**
 * Mirror private-backend witnessLogService.buildConsistencyProof root computation.
 * @param {unknown} proof
 * @param {string[]} entryDigests — digests for indices [from_index … to_index] inclusive
 */
export function verifyWitnessConsistencyProof(proof, entryDigests = []) {
  const result = {
    schema: 'aevesa.witness-consistency-verify/v1',
    ok: false,
    checks: {
      schemaValid: false,
      rangeValid: false,
      digestCountMatches: false,
      rootHashMatches: false,
    },
    errors: [],
  };

  if (!proof || typeof proof !== 'object') {
    result.errors.push('consistency_proof missing');
    return result;
  }

  result.checks.schemaValid = proof.schema === WITNESS_CONSISTENCY_PROOF_SCHEMA;
  if (!result.checks.schemaValid) {
    result.errors.push('invalid consistency proof schema');
    return result;
  }

  const from = Number(proof.from_index);
  const to = Number(proof.to_index);
  const count = Number(proof.entry_count);
  result.checks.rangeValid =
    Number.isInteger(from)
    && Number.isInteger(to)
    && from >= 0
    && to >= from
    && count === to - from + 1;

  if (!result.checks.rangeValid) {
    result.errors.push('invalid consistency proof index range');
    return result;
  }

  const digests = (entryDigests || [])
    .map((d) => String(d || '').trim().toLowerCase())
    .filter((d) => HEX64.test(d));

  result.checks.digestCountMatches = digests.length === count;
  if (!result.checks.digestCountMatches) {
    result.errors.push('entry digest count does not match proof range');
    return result;
  }

  const expectedRoot = sha256Utf8(JSON.stringify(digests));
  const rootHash = String(proof.root_hash || '').trim().toLowerCase();
  result.checks.rootHashMatches = HEX64.test(rootHash) && rootHash === expectedRoot;
  if (!result.checks.rootHashMatches) {
    result.errors.push('root_hash mismatch — log may have equivocated or proof is stale');
  }

  result.ok =
    result.checks.schemaValid
    && result.checks.rangeValid
    && result.checks.digestCountMatches
    && result.checks.rootHashMatches;

  return result;
}

export default { verifyWitnessConsistencyProof, WITNESS_CONSISTENCY_PROOF_SCHEMA };
