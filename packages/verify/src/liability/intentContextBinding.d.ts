import type { ParsedLiabilityReceipt } from './schema.js';

export interface IntentContextBindingResult {
  ok: boolean;
  error?: string;
}

export declare function verifyIntentContextLedgerBinding(
  receipt: ParsedLiabilityReceipt,
  ledgerDocument?: Record<string, unknown> | null,
): IntentContextBindingResult;
