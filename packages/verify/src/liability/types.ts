export const LIABILITY_RECEIPT_SCHEMA = 'liability-receipt/v1' as const;
export const AEGIS_LEDGER_SPEC = 'aegis/1' as const;

export interface VerificationResult {
  isValid: boolean;
  error?: string;
  details?: {
    chainLength: number;
    pillarsValidated: string[];
  };
}

/** Proof-of-Intent — agent rationale bound into receipt_digest and aegis/1 governanceBinding. */
export interface IntentContext {
  reasoning_summary: string;
  model_fingerprint: string;
}

export type LiabilityReceiptV1 = Record<string, unknown>;
