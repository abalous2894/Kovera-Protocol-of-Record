import { WITNESS_INCLUSION_PROOF_SCHEMA } from '../witness/witnessInclusionVerify.js';

/** Wave 14 Track G — witness diversity assertions (INT-04). */

export const WITNESS_DIVERSITY_BLOCK_SCHEMA = 'aevesa.witness-diversity/v1' as const;

export const DEFAULT_MIN_WITNESS_LOGS = 2;
export const DEFAULT_MIN_WITNESS_OPERATORS = 2;

export interface WitnessDiversityInclusionProof {
  schema: string;
  log_id: string;
  org_id?: string;
  operator_id?: string;
  entry_index: number;
  entry_id?: string;
  root_hash: string;
  parent_hash?: string;
  issued_at?: string;
}

export interface WitnessDiversityBlockInput {
  inclusion_proofs: WitnessDiversityInclusionProof[];
  min_logs?: number;
  min_operators?: number;
}

export interface WitnessDiversityBlock {
  schema: typeof WITNESS_DIVERSITY_BLOCK_SCHEMA;
  log_count: number;
  operator_count: number;
  min_logs_required: number;
  min_operators_required: number;
  inclusion_proofs: WitnessDiversityInclusionProof[];
  diversity_met: boolean;
}

const HEX64 = /^[a-f0-9]{64}$/;

export function resolveWitnessOperatorId(proof: WitnessDiversityInclusionProof): string {
  const operator = String(proof.operator_id || proof.org_id || proof.log_id || '').trim();
  return operator.toLowerCase();
}

export function normalizeWitnessDiversityProofs(
  proofs: WitnessDiversityInclusionProof[],
): WitnessDiversityInclusionProof[] {
  return [...(proofs || [])]
    .map((proof) => ({
      schema: String(proof.schema || '').trim(),
      log_id: String(proof.log_id || '').trim(),
      org_id: proof.org_id != null ? String(proof.org_id).trim() : undefined,
      operator_id: proof.operator_id != null ? String(proof.operator_id).trim() : undefined,
      entry_index: Number(proof.entry_index) || 0,
      entry_id: proof.entry_id != null ? String(proof.entry_id).trim() : undefined,
      root_hash: String(proof.root_hash || '').trim().toLowerCase(),
      parent_hash:
        proof.parent_hash != null ? String(proof.parent_hash).trim().toLowerCase() : undefined,
      issued_at: proof.issued_at != null ? String(proof.issued_at).trim() : undefined,
    }))
    .sort((a, b) => {
      const byLog = a.log_id.localeCompare(b.log_id);
      if (byLog !== 0) return byLog;
      return a.entry_index - b.entry_index;
    });
}

export function countDistinctWitnessLogs(proofs: WitnessDiversityInclusionProof[]): number {
  const logs = new Set(
    (proofs || []).map((proof) => String(proof.log_id || '').trim().toLowerCase()).filter(Boolean),
  );
  return logs.size;
}

export function countDistinctWitnessOperators(proofs: WitnessDiversityInclusionProof[]): number {
  const operators = new Set(
    (proofs || []).map((proof) => resolveWitnessOperatorId(proof)).filter(Boolean),
  );
  return operators.size;
}

export function deriveWitnessDiversityMet(
  logCount: number,
  operatorCount: number,
  minLogs: number,
  minOperators: number,
): boolean {
  return logCount >= minLogs && operatorCount >= minOperators;
}

export function buildWitnessDiversityBlock(input: WitnessDiversityBlockInput): WitnessDiversityBlock {
  const inclusion_proofs = normalizeWitnessDiversityProofs(input.inclusion_proofs || []);
  const min_logs_required = Number(input.min_logs) || DEFAULT_MIN_WITNESS_LOGS;
  const min_operators_required = Number(input.min_operators) || DEFAULT_MIN_WITNESS_OPERATORS;
  const log_count = countDistinctWitnessLogs(inclusion_proofs);
  const operator_count = countDistinctWitnessOperators(inclusion_proofs);
  const diversity_met = deriveWitnessDiversityMet(
    log_count,
    operator_count,
    min_logs_required,
    min_operators_required,
  );

  return {
    schema: WITNESS_DIVERSITY_BLOCK_SCHEMA,
    log_count,
    operator_count,
    min_logs_required,
    min_operators_required,
    inclusion_proofs,
    diversity_met,
  };
}

export function isWitnessInclusionProofStructurallyValid(proof: WitnessDiversityInclusionProof): boolean {
  return (
    proof.schema === WITNESS_INCLUSION_PROOF_SCHEMA
    && String(proof.log_id || '').trim().length > 0
    && Number.isFinite(proof.entry_index)
    && proof.entry_index >= 0
    && HEX64.test(String(proof.root_hash || '').toLowerCase())
  );
}

export default {
  WITNESS_DIVERSITY_BLOCK_SCHEMA,
  DEFAULT_MIN_WITNESS_LOGS,
  DEFAULT_MIN_WITNESS_OPERATORS,
  buildWitnessDiversityBlock,
  normalizeWitnessDiversityProofs,
  countDistinctWitnessLogs,
  countDistinctWitnessOperators,
  deriveWitnessDiversityMet,
  isWitnessInclusionProofStructurallyValid,
  resolveWitnessOperatorId,
};
