import {
  canonicalizeCausalLineageForDigest,
  extractCausalLineageFromPayload,
} from '../core/causalLineage.js';

/**
 * When a receipt carries causal_lineage, optional ledger row data must expose the same parent anchor.
 * @param {import('./schema.js').ParsedLiabilityReceipt} receipt
 * @param {Record<string, unknown> | null | undefined} [ledgerDocument]
 */
export function verifyCausalLineageLedgerBinding(receipt, ledgerDocument) {
  if (!receipt.causal_lineage) {
    return { ok: true };
  }

  const receiptLineage = canonicalizeCausalLineageForDigest(receipt.causal_lineage);
  if (!receiptLineage) {
    return { ok: false, error: 'causal_lineage present but parent_entry_hash is invalid' };
  }

  if (!ledgerDocument) {
    return { ok: true };
  }

  const payload =
    ledgerDocument.payload && typeof ledgerDocument.payload === 'object' ? ledgerDocument.payload : {};
  const fromLedger = extractCausalLineageFromPayload(payload);
  if (!fromLedger) {
    return {
      ok: false,
      error:
        'causal_lineage on receipt but ledger payload has no parentEntryHash — delegation binding cannot be verified',
    };
  }

  const ledgerCanon = canonicalizeCausalLineageForDigest(fromLedger);
  if (JSON.stringify(ledgerCanon) !== JSON.stringify(receiptLineage)) {
    return {
      ok: false,
      error: 'causal_lineage on receipt does not match parentEntryHash sealed in ledger payload',
    };
  }

  return { ok: true };
}
