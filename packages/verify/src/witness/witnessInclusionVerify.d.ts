export const WITNESS_INCLUSION_PROOF_SCHEMA: string;
export const WITNESS_GENESIS_HASH: string;
export const SCITT_REFUSAL_WITNESS_VERIFY_SCHEMA: string;
export const SCITT_REFUSAL_STATEMENT_TYPE: string;
export const REKOR_WITNESS_METADATA_SCHEMA: string;

export function calculateWitnessEntryHash(ledgerEntry: object, sequence: number): string;

export function verifyWitnessInclusionProof(
  inclusionProof: unknown,
  ledgerAppend: unknown,
  verificationExport?: unknown,
): Record<string, unknown>;

export function verifyExternalRekorWitness(
  rekorMeta: unknown,
  digestHex: string,
): Record<string, unknown>;

export function verifyExternalRekorWitnessWithInclusion(
  rekorMeta: unknown,
  digestHex: string,
  inclusionProof?: unknown,
  options?: { requireInclusionProof?: boolean; expectedLogId?: string | null },
): Record<string, unknown>;

export const REKOR_INCLUSION_PROOF_REQUIRED: string;
export const REKOR_INCLUSION_DIGEST_MISMATCH: string;

export function resolveRequireRekorInclusionProof(input: Record<string, unknown>): boolean;

export function verifyScittRefusalWitnessBundle(bundle: unknown): Record<string, unknown>;
