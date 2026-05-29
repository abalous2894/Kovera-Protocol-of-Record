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

export type LiabilityReceiptV1 = Record<string, unknown>;
