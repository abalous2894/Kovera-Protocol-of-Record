import type { ParsedLiabilityReceipt } from './schema.js';

export interface CausalLineageBindingResult {
  ok: boolean;
  error?: string;
}

export declare function verifyCausalLineageLedgerBinding(
  receipt: ParsedLiabilityReceipt,
  ledgerDocument?: Record<string, unknown> | null,
): CausalLineageBindingResult;
