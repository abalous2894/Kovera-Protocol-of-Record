/**
 * Browser bundle entry — Tier A client-side liability-receipt/v1 verification.
 * Import subpaths directly (not dist/index.js) so esbuild never pulls node-only CLI/offline exports.
 */
export { verifyReceipt } from '../dist/liability/verifyReceipt.js';
export { parseLiabilityReceiptStructure } from '../dist/liability/schema.js';
export {
  computeReceiptDigest,
  computeCanonicalReceiptDigest,
  receiptDigestPreimage,
  verifyReceiptDigestMatch,
  RECEIPT_DIGEST_PROFILE_ORDER,
} from '../dist/liability/digest.js';
export {
  evaluateIntentAlignment,
  normalizeStructuralPayload,
} from '../dist/core/intentAlignment.js';
