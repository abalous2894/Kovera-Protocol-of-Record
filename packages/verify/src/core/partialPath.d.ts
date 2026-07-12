export const PARTIAL_PATH_SCHEMA: 'aevesa.partial-path/v1';

export function verifyPartialPathCommitment(partialPath: unknown): {
  ok: boolean;
  code: string;
  expected?: string;
  got?: string;
};

export function canonicalizePartialPathForDigest(raw: unknown): Record<string, unknown> | null;
