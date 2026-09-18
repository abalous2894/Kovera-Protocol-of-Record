export const REKOR_INCLUSION_PROOF_SCHEMA: string;
export const REKOR_INCLUSION_VERIFY_SCHEMA: string;
export const REKOR_INCLUSION_PROOF_REQUIRED: string;
export const REKOR_INCLUSION_DIGEST_MISMATCH: string;

export function rfc6962LeafHash(bodyBytes: Buffer | Uint8Array): string;
export function rfc6962NodeHash(leftHex: string, rightHex: string): string;
export function computeRfc6962RootFromInclusionProof(input: {
  leafIndex: number;
  treeSize: number;
  leafHashHex: string;
  hashesHex: string[];
}): { ok: boolean; rootHex: string | null; errors: string[] };
export function computeRekorLeafHashFromBodyBase64(entryBodyBase64: string): string;
export function buildHashedRekordEntryBodyJson(digestHex: string): string;
export function buildHashedRekordEntryBodyBase64(digestHex: string): string;
export function extractHashedRekordDigestFromEntryBody(
  entryBodyBase64: string,
): { ok: boolean; digest: string | null; errors: string[] };
export function buildSingleLeafRekorInclusionProofDocument(
  digestHex: string,
  opts?: { logId?: string; checkpointSuffix?: string },
): Record<string, unknown>;
export function parseRekorCheckpointEnvelope(checkpoint: string): Record<string, unknown>;
export function verifyRekorCryptoInclusionProof(
  proof: unknown,
  options?: {
    expectedLogIndex?: number | null;
    expectedLogId?: string | null;
    expectedStatementDigest?: string | null;
  },
): Record<string, unknown>;
