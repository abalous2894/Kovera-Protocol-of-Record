export const WITNESS_CONSISTENCY_PROOF_SCHEMA: string;

export function verifyWitnessConsistencyProof(
  proof: unknown,
  entryDigests?: string[],
): {
  schema: string;
  ok: boolean;
  checks: Record<string, boolean>;
  errors: string[];
};
