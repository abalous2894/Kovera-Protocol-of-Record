import { sha256HexUtf8 } from './sha256.js';
import { createHash } from 'node:crypto';
import { stableStringify } from './stableStringify.js';

export const AEG_INTEGRITY_SCHEMA = 'aevesa.aeg-integrity/v1' as const;

export const AEG_STRUCTURAL_SOURCES = ['A', 'B', 'C'] as const;
export type AegStructuralSource = (typeof AEG_STRUCTURAL_SOURCES)[number];

export const AEG_INTEGRITY_CHECKS = [
  'delegation_completeness',
  'authority_attribution',
  'scope_compliance',
  'provenance_preservation',
  'recomposition_authorization',
  'termination_comparison',
] as const;

export type AegIntegrityCheckName = (typeof AEG_INTEGRITY_CHECKS)[number];

export const AEG_CHECK_RESULTS = ['PASS', 'FAIL', 'SKIP'] as const;
export type AegCheckResult = (typeof AEG_CHECK_RESULTS)[number];

export interface AegIntegrityCheckEvaluated {
  check: AegIntegrityCheckName;
  result: AegCheckResult;
  source?: AegStructuralSource | null;
  detail?: string;
}

export interface AegIntegrityManifestInput {
  session_id: string;
  decision_id?: string;
  edge: number;
  checks_evaluated: AegIntegrityCheckEvaluated[];
  environmental_digest?: string;
  delegated_digest?: string;
}



export function computeAegIntegrityDigest(input: AegIntegrityManifestInput): string {
  const checks = [...input.checks_evaluated]
    .map((c) => ({
      check: c.check,
      result: c.result,
      ...(c.source ? { source: c.source } : {}),
      ...(c.detail ? { detail: String(c.detail).slice(0, 256) } : {}),
    }))
    .sort((a, b) => a.check.localeCompare(b.check));

  const preimage: Record<string, unknown> = {
    schema: AEG_INTEGRITY_SCHEMA,
    session_id: String(input.session_id).trim(),
    edge: input.edge,
    checks_evaluated: checks,
  };
  if (input.decision_id) preimage.decision_id = String(input.decision_id).trim();
  if (input.environmental_digest) preimage.environmental_digest = input.environmental_digest;
  if (input.delegated_digest) preimage.delegated_digest = input.delegated_digest;

  return sha256HexUtf8(stableStringify(preimage));
}
