import {
  WITNESS_DIVERSITY_BLOCK_SCHEMA,
  buildWitnessDiversityBlock,
  countDistinctWitnessLogs,
  countDistinctWitnessOperators,
  deriveWitnessDiversityMet,
  isWitnessInclusionProofStructurallyValid,
  normalizeWitnessDiversityProofs,
  type WitnessDiversityInclusionProof,
} from '../core/witnessDiversity.js';

export const WITNESS_DIVERSITY_SKU = 'aevesa-witness-diversity-v1' as const;

export interface WitnessDiversityVerifyOptions {
  requireDiversityMet?: boolean;
  minLogs?: number;
  minOperators?: number;
}

export interface WitnessDiversityVerifyResult {
  schema: typeof WITNESS_DIVERSITY_BLOCK_SCHEMA;
  sku: typeof WITNESS_DIVERSITY_SKU;
  ok: boolean;
  checks: {
    schemaValid: boolean;
    proofsPresent: boolean;
    proofsStructurallyValid: boolean;
    logCountMatches: boolean;
    operatorCountMatches: boolean;
    diversityMetConsistent: boolean;
    diversityRequirementMet: boolean;
  };
  diversity_met: boolean;
  log_count: number;
  operator_count: number;
  gtmLine: string;
  note: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseProofs(raw: unknown): WitnessDiversityInclusionProof[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((item) => item != null && typeof item === 'object')
    .map((item) => item as WitnessDiversityInclusionProof);
}

export function verifyWitnessDiversityBlock(
  blockInput: unknown,
  options: WitnessDiversityVerifyOptions = {},
): WitnessDiversityVerifyResult {
  const block = asRecord(blockInput);
  const schemaValid = block?.schema === WITNESS_DIVERSITY_BLOCK_SCHEMA;
  const proofs = parseProofs(block?.inclusion_proofs);
  const normalized = normalizeWitnessDiversityProofs(proofs);
  const proofsPresent = normalized.length > 0;
  const proofsStructurallyValid =
    proofsPresent && normalized.every((proof) => isWitnessInclusionProofStructurallyValid(proof));

  const derivedLogCount = countDistinctWitnessLogs(normalized);
  const derivedOperatorCount = countDistinctWitnessOperators(normalized);
  const minLogs = Number(block?.min_logs_required ?? options.minLogs ?? 2);
  const minOperators = Number(block?.min_operators_required ?? options.minOperators ?? 2);
  const derivedDiversityMet = deriveWitnessDiversityMet(
    derivedLogCount,
    derivedOperatorCount,
    minLogs,
    minOperators,
  );

  const logCountMatches = Number(block?.log_count) === derivedLogCount;
  const operatorCountMatches = Number(block?.operator_count) === derivedOperatorCount;
  const diversityMetConsistent = block?.diversity_met === derivedDiversityMet;
  const requireDiversityMet = options.requireDiversityMet === true;
  const diversityRequirementMet = !requireDiversityMet || derivedDiversityMet === true;

  const ok =
    schemaValid
    && proofsPresent
    && proofsStructurallyValid
    && logCountMatches
    && operatorCountMatches
    && diversityMetConsistent
    && diversityRequirementMet;

  let note: string | null = null;
  if (!proofsPresent) note = 'inclusion_proofs missing';
  else if (!proofsStructurallyValid) note = 'inclusion proof structural validation failed';
  else if (!logCountMatches || !operatorCountMatches) note = 'witness diversity counts mismatch proofs';
  else if (!diversityMetConsistent) note = 'diversity_met inconsistent with proof counts';
  else if (!diversityRequirementMet) note = 'witness diversity minimum not met';

  return {
    schema: WITNESS_DIVERSITY_BLOCK_SCHEMA,
    sku: WITNESS_DIVERSITY_SKU,
    ok,
    checks: {
      schemaValid: schemaValid === true,
      proofsPresent: proofsPresent === true,
      proofsStructurallyValid: proofsStructurallyValid === true,
      logCountMatches: logCountMatches === true,
      operatorCountMatches: operatorCountMatches === true,
      diversityMetConsistent: diversityMetConsistent === true,
      diversityRequirementMet: diversityRequirementMet === true,
    },
    diversity_met: derivedDiversityMet,
    log_count: derivedLogCount,
    operator_count: derivedOperatorCount,
    gtmLine:
      'Evidence independence means more than one operator can confirm the anchor — offline.',
    note,
  };
}

/** Recompute canonical diversity block for pack builders. */
export function recomputeWitnessDiversityBlock(
  proofs: WitnessDiversityInclusionProof[],
  minLogs?: number,
  minOperators?: number,
) {
  return buildWitnessDiversityBlock({
    inclusion_proofs: proofs,
    min_logs: minLogs,
    min_operators: minOperators,
  });
}

export default {
  verifyWitnessDiversityBlock,
  recomputeWitnessDiversityBlock,
  WITNESS_DIVERSITY_SKU,
};
