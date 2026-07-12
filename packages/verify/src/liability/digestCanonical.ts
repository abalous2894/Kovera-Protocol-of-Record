import { computeReceiptDigest, type ReceiptDigestProfile } from './digestProfiles.js';
import { parseLiabilityReceiptStructure } from './schema.js';

/** Zod-normalized pillar document used as the normative receipt_digest preimage. */
export function receiptDigestPreimage(receipt: Record<string, unknown>): Record<string, unknown> {
  const parsed = parseLiabilityReceiptStructure(receipt);
  if (!parsed.ok) return receipt;
  return parsed.receipt as unknown as Record<string, unknown>;
}

export function computeCanonicalReceiptDigest(
  receipt: Record<string, unknown>,
  options: { profile?: ReceiptDigestProfile } = {},
): string {
  return computeReceiptDigest(receiptDigestPreimage(receipt), options);
}
