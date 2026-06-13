import { canonicalizeIntentContextForBinding, serializeIntentContext } from '../core/intentContext.js';
import { verifyLedgerEntryPreimage } from '../core/ledgerPreimage.js';

/**
 * When a receipt carries intent_context, optional ledger row data can prove the
 * primary_anchor entry_hash was sealed with the same intentContext in governanceBinding.
 * @param {import('./schema.js').ParsedLiabilityReceipt} receipt
 * @param {Record<string, unknown> | null | undefined} [ledgerDocument]
 */
export function verifyIntentContextLedgerBinding(receipt, ledgerDocument) {
  if (!receipt.intent_context) {
    return { ok: true };
  }

  const receiptIntent = canonicalizeIntentContextForBinding(receipt.intent_context);

  if (ledgerDocument) {
    const preimage = verifyLedgerEntryPreimage(ledgerDocument, { verifyProofOfIntent: false });
    if (!preimage.ok) {
      const failed = preimage.layers?.find((l) => !l.pass);
      return {
        ok: false,
        error: `Ledger preimage failed with intent_context present: ${failed?.detail ?? 'entry_hash mismatch'}`,
      };
    }
    const anchorHash = String(receipt.proof.primary_anchor.entry_hash).toLowerCase();
    const recomputed = String(preimage.recomputedEntryHash || '').toLowerCase();
    if (!preimage.entryHashMatch || recomputed !== anchorHash) {
      return {
        ok: false,
        error: 'proof.primary_anchor.entry_hash does not match ledger row recomputed with intent_context binding',
      };
    }

    const payload =
      ledgerDocument.payload && typeof ledgerDocument.payload === 'object' ? ledgerDocument.payload : {};
    const storedIntentRaw =
      ledgerDocument.intentContext ?? payload.intent_context ?? payload.intentContext;
    if (storedIntentRaw != null) {
      const storedIntent = canonicalizeIntentContextForBinding(serializeIntentContext(storedIntentRaw));
      if (JSON.stringify(storedIntent) !== JSON.stringify(receiptIntent)) {
        return {
          ok: false,
          error: 'intent_context on receipt does not match intent_context sealed in ledger governance binding',
        };
      }
    }
  }

  return { ok: true };
}
